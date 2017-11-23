#!/usr/bin/perl 
use strict;
use warnings;
use feature 'say';
use utf8;
use Getopt::Long qw(GetOptions);
use JSON qw( decode_json encode_json );
use Encode;
use MongoDB;

=head1 NAME

btaminerAce.pl - a perl miner for BTA to work with NTSecurityDescriptor

=head1 SYNOPSIS

  $ ./btaminerAce.pl --help

or

  $ ./btaminerAce.pl -d dbAD -c user --json


=head1 DESCRIPTION

B<btaminerAce.pl> request a mongoDB populate by BTA L<https://bitbucket.org/iwseclabs/bta>

B<btaminerAce.pl> print ACE for users, groups, computers or GPOs with optional compact output for json or N-quads graphs.

Compact output of builtin AD groups works only for french edition.

=head2 Tips

- Inline doc with

 $ perldoc ./btaminerAce.pl

- If old mongoDB driver print "stripped unsupported regex flag /u from MongoDB regex" warning, redirect output to /dev/null

  $ ./btaminerAce.pl -d dbAD -c user 2>/dev/null

- Please use perltidy before submiting a patch

vim:

  :%!perltidy

=head2 Algorithm

=head3 - Manage command line options
=cut

####################################

sub Usage {
    say "
 Usage: $0 -d <dbname> -c <[user|group|computer|gpo]> 
    options:
    --json        affichage json pour affichage OVALI
    --quad        affichage quad pour traitement 
    --user cn='nom prenom (DOM)'   que pour les utilisateurs 
    --user cn=login                autre utilisateur  
    --full        affiche toutes les auth. ou que les nlles
    --host        defaut : localhost
    --port        defaut : 27017
    --help
    ";
    exit 0;
}

my $dbname = "";
my $check  = "";
my $json   = 0;
my $quad   = 0;
my $full   = 0;
my $help   = 0;
my $host   = 'localhost';
my $port   = 27017;
my $max    = 20;          # Max number of objects with same nTSecurityDescriptor
my %users  = ();

GetOptions(
    'dbname=s' => \$dbname,
    'check=s'  => \$check,
    'user=s%'  => sub { push( @{ $users{ $_[1] } }, { cn => $_[2] } ) },
    'json'     => \$json,
    'quad'     => \$quad,
    'full'     => \$full,
    'help'     => \$help,
    'host'     => \$host,
    'port'     => \$port
);

&Usage if $help;

my $checkType = "";

if ( $check eq 'user' ) {
    $checkType = "user";
}
elsif ( $check eq 'group' ) {
    $checkType = "GROUP";
}
elsif ( $check eq 'computer' ) {
    $checkType = "computer";
}
elsif ( $check eq 'gpo' ) {
    $checkType = "GroupPOlicycontainer";
}

&Usage
  if !$dbname || !$checkType;

&Usage
  if $json && $quad;

&Usage
  if %users && $check ne 'user';

my $print = 0;
$print = 1 if !$json && !$quad;

=head3 - Prepare mongo requests
=cut

################################

my $client = MongoDB::MongoClient->new( host => $host, port => $port );
my $db     = $client->get_database($dbname);
my $table  = $db->get_collection('datatable');
my $link   = $db->get_collection('link_table');
my $sd     = $db->get_collection('sd_table');
my $guid   = $db->get_collection('guid');

my %Match = (
    GroupPOlicycontainer => { 'objectClass' => '1.2.840.113556.1.5.157' }, # GPO
    user                 => { 'objectClass' => '1.2.840.113556.1.5.9' },
    userxx               => {
        '$and' => [
            { 'objectClass'    => '1.2.840.113556.1.5.9' },
            { 'objectCategory' => 3372 } # 3156 for 2008 server
        ]
    },
    GROUP    => { 'objectClass' => '1.2.840.113556.1.5.8' },
    computer => { 'objectClass' => '1.2.840.113556.1.3.30' }
    ,    #computer is a user subclass!
    domaincontroller   => { 'objectClass' => '1.2.840.113556.1.5.17' },  #server
    OrganizationalUnit => { 'objectClass' => '2.5.6.5' },                #OU
    RoDomainController =>
      { 'objectClass' => '1.2.840.113556.1.5.34' }    # TrustedDomains
);

if (%users) {
    $Match{user} = { '$or' => $users{cn} };
}

my $match = {
    '$and' => [
        $Match{$checkType},
        {
            '$or' =>
              [ { 'isDeleted' => 0 }, { 'isDeleted' => { '$exists' => 0 } } ]
        }

    ]
};

# Security identifier
# https://support.microsoft.com/en-us/kb/243330
my %SID = (
    'S-1-5-4'  => 'users logged on interactively',
    'S-1-5-9'  => 'Enterprise Domain Controllers',
    'S-1-5-11' => 'Authenticated Users',
);
my %Type = (
    '1.2.840.113556.1.5.9'  => 'User',
    '1.2.840.113556.1.5.8'  => 'GROUP',
    '1.2.840.113556.1.5.76' => 'foreignSecurityPrincipal',
    '1.2.840.113556.1.5.77' => 'controlAccessRight',
    '1.2.840.113556.1.3.14' => 'attributeSchema',
    '1.2.840.113556.1.3.13' => 'classSchema',
    '1.2.840.113556.1.3.30' => 'computer'
);

my @Builtin = (    # for french edition :-/
    'Éditeurs de certificats',
    'Groupe d’accès d’autorisation Windows',
    'Authenticated Users',
    'Administrateurs de l’entreprise',
    'Opérateurs d’impression',
    'Admins du domaine',
    'Utilisateurs du domaine',
    'Administrateurs',
    'Utilisateurs du domaine',
    'Serveurs RAS et IAS',
    'Serveurs de licences des services Terminal Server',
    'Opérateurs de compte',
    'Accès compatible pré-Windows 2000',
    'Authenticated Users',
    'Enterprise Domain Controllers',
    'Self',
    'Everyone',
    'System',
    'Creator Owner',
);

my @BuiltinID = ();

my $nodeid = 0;
my %nodes  = ();
my @links  = ();

my %Owner  = ();
my %Object = ();

# Manage nodes
sub node {
    my $name = shift;
    my $type = shift;
    my $dist = shift;

    # Cache
    return $nodes{$name} if $nodes{$name};

    $nodeid++;
    my %n = (
        type      => lc($type),
        id        => $nodeid,
        shortname => $name,
        name      => $name,
        dist      => $dist
    );

    # store builtin objects
    push @BuiltinID, $nodeid if grep /^$name$/, @Builtin;

    $nodes{$name} = \%n;

    return $nodes{$name};
}

=head3 - INIT : create a BUILTIN group
=cut

######################################

my $bnode = node( "BUILTIN", "Group", 20 );

# Manage links
sub addLink {
    my $l    = shift;
    my $acel = shift;

    # Group builtin by adding links between builtin object and target
    if (
        ( $l->{target} != $bnode->{id} && $l->{source} != $bnode->{id} )
        && grep /^$l->{source}$/,
        @BuiltinID
      )
    {
        my %lbuiltin = (
            source => $l->{source},
            target => $bnode->{id},
            rels   => ["is_member"]
        );
        my %ltarget = (
            source => $bnode->{id},
            target => $l->{target},
            rels   => [ "has_access", "is_writer" ]
        );
        addLink( \%lbuiltin );
        addLink( \%ltarget );
        return;
    }

    # Add unique link
    if (
        !grep {
                 $_->{source} == $l->{source}
              && $_->{target} == $l->{target}
              && $_->{rels}[0] eq $l->{rels}[0]
        } @links
      )
    {
        push @links, $l;
        push @$acel, $l if $acel;
    }
}

# Find object by GUID
# create link to nTSecurityDescriptor
sub findObject {
    no warnings 'uninitialized';
    my $obj        = shift;
    my $inHeritObj = shift;
    return if !$obj;

    # Cache
    if ( $Object{$obj} ) {
        return split ' : ', $Object{$obj};
    }
    my $nobj = $table->find_one(

        #{ 'rightsGuid' => qr/$obj/soi },
        { 'rightsGuid' => $obj },
        {
            'cn'                   => 1,
            'name'                 => 1,
            'objectClass'          => 1,
            'userAccountControl'   => 1,
            'nTSecurityDescriptor' => 1
        }
    );    #if !$inHeritObj;
    $nobj = $table->find_one(

        #{ 'schemaIDGUID' => qr/$obj/soi },
        { 'schemaIDGUID' => $obj },
        {
            'cn'                   => 1,
            'name'                 => 1,
            'objectClass'          => 1,
            'userAccountControl'   => 1,
            'nTSecurityDescriptor' => 1
        }
    ) if !$nobj;
    $nobj = $guid->find_one( { 'id' => $obj } ) if !$nobj;

#    return " " if !$nobj->{'userAccountControl'}->{'flags'}->{'accountDisable'};

    my $n     = $nobj->{name} || $nobj->{cn} || $obj;
    my $sd    = $nobj->{'nTSecurityDescriptor'};
    my %types = map { $_ => 1 } @{ $nobj->{'objectClass'} };

    my $type = join ', ', @{ $nobj->{'objectClass'} };

    foreach my $t ( keys %Type ) {
        $type = $Type{$t} if $types{$t};    # Override with known types
    }

    $Object{$obj} = $type . " : " . $n . " : " . $sd;

    my $n1 = node( $n,  $type,       0 );
    my $nt = node( $sd, "nTSecDesc", 0 );
    my %ntl = (
        source => $nt->{id},
        target => $n1->{id},
        rels   => ["has_member"]
    );
    addLink( \%ntl );

    return ( $type, $n, $sd );
}

# Find Object by SID
# create link to nTSecurityDescriptor
sub findSID {
    my $sid = shift;

    # Cache
    if ( $Owner{$sid} ) {
        return split ' : ', $Owner{$sid};
    }
    my $nsid = $table->find_one(
        { 'objectSid' => qr/^$sid$/i },
        {
            'cn'                   => 1,
            'name'                 => 1,
            'objectClass'          => 1,
            'userAccountControl'   => 1,
            'nTSecurityDescriptor' => 1
        }
    );

#   return " " if !$nsid->{'userAccountControl'}->{'flags'}->{'accountDisable'};
    my $n = $nsid->{name} || $nsid->{cn} || $sid;
    my $sd = $nsid->{'nTSecurityDescriptor'};

    my %types = map { $_ => 1 } @{ $nsid->{'objectClass'} };
    my $type = join ', ', @{ $nsid->{'objectClass'} };
    foreach my $t ( keys %Type ) {
        $type = $Type{$t} if $types{$t};    # Override with known types
    }

    $Owner{$sid} = $type . " : " . $n . " : " . $sd;

    my $n1 = node( $n,  $type,       0 );
    my $nt = node( $sd, "nTSecDesc", 0 );
    my %ntl = (
        source => $nt->{id},
        target => $n1->{id},
        rels   => ["has_member"]
    );
    addLink( \%ntl );

    return ( $type, $n, $sd );
}

my %TemplateACE = ();
my %SEC         = ();

# Read ACE by nTSecDesc
sub getACEs {
    my $nTSecDesc = shift;
    my $title     = shift;
    my $acelist   = shift;

    my $n1 = node( $title, $checkType, 0 );
    $SEC{$nTSecDesc}->{nodeid} = $n1->{id};

    my @ACEs = ();
    my @ACEl = ();
    foreach my $ace (@$acelist) {
        no warnings 'uninitialized';
        my $obj  = $ace->{ObjectType};
        my $objh = $ace->{InheritedObjectType};
        my $sid  = $ace->{SID};

        #next if $objh; # don't manage inherited object ?

        my $aMask = $ace->{AccessMask}->{value};
        my ( $nt, $n, $nsd ) = findObject( $obj, 0 ) if $full;
        my ( $nth, $nh, $nhsd ) = findObject( $objh, 1 ) if $objh && $full;
        my $flags = $ace->{AccessMask}->{flags};
        my @f     = ();
        foreach my $t ( sort keys %$flags ) {
            if ($full) {
                push @f, $t
                  if $flags->{$t};
            }
            else {
                if (
                    $flags->{$t}
                    && (   $t =~ m/Write/
                        || $t =~ m/Delete/ )

                    #|| $t =~ m/Control/i )
                  )
                {
                    push @f, $t;

                }
            }
        }
        my $listflags = ( join ',', @f );
        my ( $tsid, $nsid, $sidsd ) = findSID($sid);
        my $short_ace = "";
        $short_ace = encode( 'utf8',
                "   "
              . $ace->{Type}
              . " | ($aMask) "
              . $listflags . " "
              . "$nt: $n" . " | "
              . "$nth: $nh" . " | "
              . "$tsid: $nsid" );

        push( @ACEs, $short_ace ) unless grep { $_ eq $short_ace } @ACEs;

        my $n2 = node( $nsid, $tsid, 1 );
        my %l = (
            source => $n2->{id},
            target => $n1->{id},
            rels   => ["has_access"]
        );
        my $writer = 0;
        if (   $listflags =~ m/Write/
            || $listflags =~ m/Delete/ )

       #|| $listflags =~ m/Control/i ) # XXX ADSRightDSControlAccess is writer ?
        {
            push @{ $l{rels} }, "is_writer";
            $writer = 1;
        }
        addLink( \%l, \@ACEl );

        if ($nh) {
            my $n3 = node( $nh, $nth, 1 );
            my %l2 = (
                source => $n3->{id},
                target => $n2->{id},
                rels   => ["inherit"]
            );
            addLink( \%l2, \@ACEl );
        }
    }

    return \@ACEl if !$print;

    foreach my $lace (@ACEs) {
        next if !$lace;
        $TemplateACE{$lace}++;
        if ($full) {
            say $lace . " == " . $TemplateACE{$lace};
        }
        else {
            say $lace if $TemplateACE{$lace} == 1;
        }
    }
    return \@ACEl;
}

# Manage other objects with same nTSecDesc
sub otherObjects {
    my $nTSecDesc = shift;
    my $mTitle    = shift;
    my $size      = scalar( @{ $SEC{$nTSecDesc}->{name} } );
    say " nb objects: " . $size if ($print);
    my $nt = node( $nTSecDesc, "nTSecDesc", 0 );

    my $n = node( $mTitle, $checkType, $size );
    $n->{dist} = $size;

    my %l1 = (
        source => $nt->{id},
        target => $n->{id},
        rels   => ["has_member"]
    );
    addLink( \%l1 );

    return if !$full;

    # XXX certainly need more love
    if (   scalar( @{ $SEC{$nTSecDesc}->{name} } ) < 15
        && scalar( @{ $SEC{$nTSecDesc}->{name} } ) > 1 )
    {
        #if ( scalar( @{ $SEC{$nTSecDesc}->{name} } ) < 15 ) {

        say "  " . encode( 'utf8', join ', ', @{ $SEC{$nTSecDesc}->{name} } )
          if $print;

        # Copy same ACE
        foreach my $title ( @{ $SEC{$nTSecDesc}->{name} } ) {
            my $n1 = node( $title, $checkType, 0 );
            $n1->{dist} = $size;
            my %ntl = (
                source => $nt->{id},
                target => $n1->{id},
                rels   => ["has_member"]
            );
            addLink( \%ntl );

            if ($full) {
                foreach my $l ( @{ $SEC{$nTSecDesc}->{ACEl} } ) {
                    my %newl = (
                        source => $l->{source},
                        rels   => $l->{rels},
                        target => $n1->{id}
                    );
                    addLink( \%newl );
                }
            }
        }
    }
}

my $oldsec   = "";
my $oldTitle = "";

=head3 - Request and main loop to find nTSecDesc by object type
=cut

###############################################################

my $data = $table->find(
    $match,
    {
        'nTSecurityDescriptor' => 1,
        'cn'                   => 1,
        'name'                 => 1,
        'displayname'          => 1,
        'userAccountControl'   => 1
    }
);    #->limit(3);

while ( my $row = $data->next ) {
    my $mainTitle = $row->{'displayName'} || $row->{'name'};
    next if $row->{'userAccountControl'}->{'flags'}->{'accountDisable'};
    next if $mainTitle =~ m/DEL:/m;

    # Cache
    my $nTSecDesc = $row->{'nTSecurityDescriptor'};
    if ( $SEC{$nTSecDesc} ) {
        push @{ $SEC{$nTSecDesc}->{name} }, $mainTitle
          if scalar( @{ $SEC{$oldsec}->{name} } ) < $max;
        next;
    }
    push @{ $SEC{$nTSecDesc}->{name} }, $mainTitle;

    otherObjects( $oldsec, $oldTitle ) if $oldsec;

    $oldsec   = $nTSecDesc;
    $oldTitle = $mainTitle;

    #$title .= " (" . $row->{'cn'} . ")" if $row->{'displayName'};
    if ($print) {
        say "=="
          . encode( 'utf8', $mainTitle ) . " ("
          . $row->{'objectSid'} . ") =="
          . $row->{'userAccountControl'}->{'flags'}->{'accountDisable'} . '==';
        say " " . $nTSecDesc;
    }

    # find nTSecDesc owner
    my $r   = $sd->find_one( { 'sd_id' => $nTSecDesc } );
    my $sid = $r->{'sd_value'}->{'Owner'};
    my $own = join ' : ', findSID($sid);
    say " nTSecurityDescriptor Owner: " . encode( 'utf8', $own ) if $print;

    my $ACEl =
      getACEs( $nTSecDesc, $mainTitle, $r->{'sd_value'}->{DACL}->{ACEList} );
    $SEC{$nTSecDesc}->{ACEl} = $ACEl;

}

=head3 - POST treatment for output

=head3
=cut

###################################

otherObjects( $oldsec, $oldTitle ) if $oldsec;

# Print results
my @tabNodes = ();
my %idNodes  = ();

#( sort {$nodes{$a}->{id} => $nodes{$b}->{id}} keys %nodes) {
foreach my $n ( keys %nodes ) {
    push @tabNodes, $nodes{$n};    #if $nodes{$n}->{type} ne "empty_grp";
    $idNodes{ $nodes{$n}->{id} } = $nodes{$n}->{name};
    say encode( 'utf8',
        '"' . $nodes{$n}->{name} . '" <type> "' . $nodes{$n}->{type} . '" .' )
      if ($quad);
}

if ($quad) {
    foreach my $l (@links) {
        my $source = $idNodes{ $l->{source} };
        my $target = $idNodes{ $l->{target} };
        say encode( 'utf8',
            '"' . $source . '" <' . $l->{rels}[0] . '> "' . $target . '" .' );
    }
}

if ($json) {
    my %json = ( "links" => \@links, "nodes" => \@tabNodes );

    say encode_json( \%json ) if ($json);
}

=head1 AUTHOR


Yves Agostini <yvesago@cpan.org>


=head1 COPYRIGHT

Copyright 2017 Yves Agostini - <yvesago@cpan.org>

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.
The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

A small fork of OVALI to watch json graphs : L<https://github.com/yvesago/OVALI>

JRES 2017: L<https://conf-ng.jres.org/2017/document_revision_2002.html?download>
