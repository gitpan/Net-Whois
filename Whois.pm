# -*- mode:Perl -*-
# $Id: Whois.pm,v 1.4 1997/05/23 03:40:00 chip Beta $

package Net::Whois;
BEGIN { require 5.003 }
use strict;

=head1 NAME

Net::Whois - Get and parse "whois" data from InterNIC

=head1 SYNOPSIS

    my $w = new Net::Whois::Domain $dom
        or die "Can't find info on $dom\n";
    #
    # Note that all fields except "name" and "tag" may be undef
    #   because "whois" information is erratically filled in.
    #
    print "Domain: ", $w->domain, "\n";
    print "Name: ", $w->name, "\n";
    print "Tag: ", $w->tag, "\n";
    print "Address:\n", map { "    $_\n" } $w->address;
    print "Country: ", $w->country, "\n";
    print "Servers:\n", map { "    $$_[0] ($$_[1])\n" } @{$w->servers};
    my ($c, $t);
    if ($c = $w->contacts) {
        print "Contacts:\n";
        for $t (sort keys %$c) {
            print "    $t:\n";
            print map { "\t$_\n" } @{$$c{$t}};
        }
    }

    $cur_server = Net::Whois::server;
    Net::Whois::server 'new.whois.server';  # optional

=head1 DESCRIPTION

Net::Whois::Domain new() attempts to retrieve and parse the given
domain's "whois" information from the InterNIC.  If the constructor
returns a reference, that reference can be used to access the various
attributes of the domains' whois entry.

Note that the Locale::Country module (part of the Locale-Codes
distribution) is used to recognize spelled-out country names; if that
module is not present, only two-letter country abbreviations will be
recognized.

The server consulted is "whois.internic.net", unless this is changed
by a call to Net::Whois::server().

=head1 AUTHOR

Originally written by Chip Salzenberg in April of 1997 for Idle
Communications, Inc.

=head1 COPYRIGHT

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

use IO::Socket;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = '0.21';

require Exporter;
@ISA = qw(Exporter);
@EXPORT = ();

my $server_name = 'whois.internic.net';
my $server_addr;

my %US_State = (
	AL => 'ALABAMA',
	AK => 'ALASKA',
	AZ => 'ARIZONA',
	AR => 'ARKANSAS',
	CA => 'CALIFORNIA',
	CO => 'COLORADO',
	CT => 'CONNECTICUT',
	DE => 'DELAWARE',
	DC => 'DISTRICT OF COLUMBIA',
	FL => 'FLORIDA',
	GA => 'GEORGIA',
	GU => 'GUAM',
	HI => 'HAWAII',
	ID => 'IDAHO',
	IL => 'ILLINOIS',
	IN => 'INDIANA',
	IA => 'IOWA',
	KS => 'KANSAS',
	KY => 'KENTUCKY',
	LA => 'LOUISIANA',
	ME => 'MAINE',
	MH => 'MARSHALL ISLANDS',
	MD => 'MARYLAND',
	MA => 'MASSACHUSETTS',
	MI => 'MICHIGAN',
	MN => 'MINNESOTA',
	MS => 'MISSISSIPPI',
	MO => 'MISSOURI',
	MT => 'MONTANA',
	'NE' => 'NEBRASKA',
	NV => 'NEVADA',
	NH => 'NEW HAMPSHIRE',
	NJ => 'NEW JERSEY',
	NM => 'NEW MEXICO',
	NY => 'NEW YORK',
	NC => 'NORTH CAROLINA',
	ND => 'NORTH DAKOTA',
	MP => 'NORTHERN MARIANA ISLANDS',
	OH => 'OHIO',
	OK => 'OKLAHOMA',
	OR => 'OREGON',
	PA => 'PENNSYLVANIA',
	PR => 'PUERTO RICO',
	RI => 'RHODE ISLAND',
	SC => 'SOUTH CAROLINA',
	SD => 'SOUTH DAKOTA',
	TN => 'TENNESSEE',
	TX => 'TEXAS',
	UT => 'UTAH',
	VT => 'VERMONT',
	VI => 'VIRGIN ISLANDS',
	VA => 'VIRGINIA',
	WA => 'WASHINGTON',
	WV => 'WEST VIRGINIA',
	WI => 'WISCONSIN',
	WY => 'WYOMING',
);
@US_State{values %US_State} = keys %US_State;

#
# Simple function.
# Call as C< Net::Whois::server 'new.server.name' >.
#
sub server {
    my $ret = $server_name;
    if (@_) {
	$server_name = $_[0];
	undef $server_addr;
    }
    $ret;
}

sub _connect {
    unless ($server_addr) {
	my $a = gethostbyname $server_name;
	$server_addr = inet_ntoa($a) if $a;
    }
    $server_addr or croak 'Net::Whois:: no server';

    my $sock = IO::Socket::INET->new(PeerAddr => $server_addr,
				     PeerPort => 'whois',
				     Proto => 'tcp')
	or croak "Net::Whois: Can't connect to $server_name: $@";
    $sock->autoflush;
    $sock;
}

#----------------------------------------------------------------
# Net::Whois::Domain
#----------------------------------------------------------------

package Net::Whois::Domain;
use Carp;

BEGIN {
    if (eval { require Locale::Country }) {
	Locale::Country->import(qw(code2country country2code));
    }
    else {
	*code2country = sub { ($_[0] =~ /^[^\W\d_]{2}$/i) && $_[0] };
	*country2code = sub { undef };
    }
}

sub new {
    my $class = @_ ? shift : 'Net::Whois';
    @_ == 1 or croak "usage: new $class DOMAIN";
    my ($domain) = @_;

    my $sock = Net::Whois::_connect();
    print $sock "dom $domain\r\n";
    my $text;
    { undef $/; $text = <$sock> }
    $sock->close;

    $text || return;

    $text =~ s/^ +//gm;
    my @text = split / *\r?\n/, $text;
    my ($t, @t);

    my %info;

    $t = shift @text;
    @info{'NAME', 'TAG'} = ($t =~ /^(.*)\s+\((\S+)\)$/)
	or return;

    @t = ();
    push @t, shift @text while $text[0];
    $t = $t[$#t];
    if (! defined $t) {
	# do nothing
    }
    elsif ($t =~ /^(?:usa|u\.\s*s\.\s*a\.)$/i) {
	pop @t;
	$t = 'US';
    }
    elsif (code2country($t)) {
	pop @t;
	$t = uc $t;
    }
    elsif (my $code = country2code($t)) {
	pop @t;
	$t = uc $code;
    }
    elsif ($t =~ /,\s*([^,]+?)(?:\s+\d{5}(?:-\d{4})?)?$/) {
	$t = $US_State{uc $1} ? 'US' : undef;
    }
    else {
	undef $t;
    }
    $info{ADDRESS} = [@t];
    $info{COUNTRY} = $t;

    while (@text) {
	$t = shift @text;
	if ($t =~ s/^domain name:\s+(\S+)$//i) {
	    $info{DOMAIN} = $1;
	}
	elsif ($t =~ /contact.*:$/i) {
	    my @ctypes = ($t =~ /\b(\S+) contact/ig);
	    my @c;
	    while ($text[0]) {
		last if $text[0] =~ /contact.*:$/i;
		push @c, shift @text;
	    }
	    @{$info{CONTACTS}}{map {uc} @ctypes} = (\@c) x @ctypes;
	}
	elsif ($t =~ /^record created on (\S+)\.$/) {
	    $info{CREATED} = $1;
	}
	elsif ($t =~ /^record last updated on (\S+)\.$/) {
	    $info{UPDATED} = $1;
	}
	elsif ($t =~ /^domain servers/i) {
	    my @s;
	    shift @text unless $text[0];
	    while ($t = shift @text) {
		push @s, [split /\s+/, $t];
	    }
	    $info{SERVERS} = \@s;
	}
    }

    bless [\%info], $class;
}

sub domain {
    my $self = shift;
    $self->[0]->{DOMAIN};
}

sub name {
    my $self = shift;
    $self->[0]->{NAME};
}

sub tag {
    my $self = shift;
    $self->[0]->{TAG};
}

sub address {
    my $self = shift;
    my $addr = $self->[0]->{ADDRESS};
    wantarray ? @$addr : join "\n", @$addr;
}

sub country {
    my $self = shift;
    $self->[0]->{COUNTRY};
}

sub contacts {
    my $self = shift;
    $self->[0]->{CONTACTS};
}

sub servers {
    my $self = shift;
    $self->[0]->{SERVERS};
}

sub record_created {
    my $self = shift;
    $self->[0]->{RECORD_CREATED};
}

sub record_updated {
    my $self = shift;
    $self->[0]->{RECORD_UPDATED};
}

1;
