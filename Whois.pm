# -*- mode:Perl -*-
# $Id: Whois.pm,v 1.1 1997/04/22 04:17:14 chip Beta $

package Net::Whois;
BEGIN { require 5.003 }
use strict;

=head1 NAME

Net::Whois - Get and parse "whois" data from InterNIC

=head1 SYNOPSIS

    my $w = new Net::Whois $dom
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
    if (my $c = $w->contacts) {
        print "Contacts:\n";
        for my $t (sort keys %$c) {
            print "    $t:\n";
            print map { "\t$_\n" } @{$$c{$t}};
        }
    }

    $cur_server = Net::Whois::server;
    Net::Whois::server 'new.whois.server';  # optional

=head1 DESCRIPTION

Net::Whois::new() attempts to retrieve and parse the given domain's
"whois" information from the InterNIC ("whois.internic.net", unless
changed by Net::Whois::server()).  If the constructor returns a
reference, that reference can be used to access the various attributes
of the domains' whois entry.

=head1 AUTHOR

Originally written by Chip Salzenberg in April of 1997.

=head1 COPYRIGHT

This module is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

use IO::Socket;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = '0.01';

require Exporter;
@ISA = qw(Exporter);
@EXPORT = ();

my $server_name = 'whois.internic.net';
my $server_addr;

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

sub new {
    my $class = @_ ? shift : 'Net::Whois';
    @_ == 1 or croak "usage: new $class DOMAIN";
    my ($domain) = @_;

    unless ($server_addr) {
	my $a = gethostbyname $server_name;
	$server_addr = inet_ntoa($a) if $a;
    }
    $server_addr or croak 'Net::Whois::new: no server';

    my $sock = new IO::Socket(Domain => AF_INET,
			      PeerAddr => $server_addr,
			      PeerPort => 'whois',
			      Proto => 'tcp')
	or croak "Net::Whois::new: Can't connect to $server_name: $@";
    $sock->autoflush;
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
    elsif ($t =~ /^[A-Z]{2,3}$/) {
	pop;
	$t = 'US' if $t =~ /^usa$/i;
    }
    elsif ($t =~ /[A-Z]{2}\s+\d{5}(?:-\d{4})?$/) {
	$t = 'US';
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
