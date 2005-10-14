# Net::MAC - Perl extension for representing and manipulating MAC addresses
# Copyright (C) 2005 Karl Ward <karlward@cpan.org>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

package Net::MAC;

use 5.008000;
use strict;
use Carp;
use warnings;

# RCS ident string
my $rcs_id = '$Id: MAC.pm,v 1.3 2005/10/14 04:28:48 karlward Exp $'; 
#@rcs_id =~ split($rcs_id); our $VERSION = $rcs_id[2]; 
our $VERSION = '1.1'; 
our $AUTOLOAD; 

# Constructor.
sub new { 
	my ($class, %arg) = @_;
	my ($self) = {}; # Anonymous hash
	bless($self, $class); # Now the hash is an object
	if (%arg) {
		$self->_init(%arg);
	}
	$self->_discover(); 
	return($self);
} 

{ # Closure for class data and class methods
#
# CLASS DATA
# 
	# These are the valid private attributes of the object, with their 
	# default values, if applicable.  
	my %_attrs = (
		'_mac' => undef, 
		'_base' => 16, 
		'_delimiter' => ':', 
		'_bit_group' => 8, 
#		'_zero_padded' => 1, 
		'_groups' => undef, 
		'_internal_mac' => undef, 
		'_die' => 1, # die() on invalid MAC address format
		'_error' => undef, 
		'_verbose' => 0
	); 
# 
# CLASS METHODS 
# 
	# Verify that an attribute is valid (called by the AUTOLOAD sub)
	sub _accessible {
		my ($self, $name) = @_;
		if (exists $_attrs{$name}) {
			#$self->verbose("attribute $name is valid");
			return 1;
		}
		else { return 0; } 
	}
	
	# Initialize the object (only called by the constructor)
	sub _init {
		my ($self, %arg) = @_;
		if (defined $arg{'verbose'}) {
			$self->{'_verbose'} = $arg{'verbose'};
			delete $arg{'verbose'};
		}
		# Set the '_die' attribute to default at the first
		$self->_default('die'); 
		foreach my $key (keys %_attrs) { 
			$key =~ s/^_+//;
			if ((defined $arg{$key}) && ($self->_accessible("_$key"))) {
				$self->verbose("setting \"$key\" to \"$arg{$key}\"");
				$self->{"_$key"} = $arg{$key};
			}
		}
		my ($mesg) = "initialized object into class " . ref($self);
		$self->verbose($mesg);
		return(1); 
	}

	# Set an attribute to its default value
	sub _default { 
		my ($self, $key) = @_;
		if ($self->_accessible("_$key") && $_attrs{"_$key"}) { 
			$self->verbose("setting \"$key\" to default value \"" . $_attrs{"_$key"} . "\"");
			$self->{"_$key"} = $_attrs{"_$key"};
			return(1); 
		}
		else { 
			$self->verbose("no default value for attribute \"$key\""); 
			return(0); # FIXME: die() here?
		}
	} 
} # End closure 

# Automatic accessor methods via AUTOLOAD
# See Object Oriented Perl, 3.3, Damian Conway
sub Net::MAC::AUTOLOAD { 
	no strict 'refs';
	my ($self, $value) = @_;
	if (($AUTOLOAD =~ /.*::get(_\w+)/) && ($self->_accessible($1))) {
		#$self->verbose("get$1 method");
		my $attr_name = $1;
		*{$AUTOLOAD} = sub { return $_[0]->{$attr_name} };
		return($self->{$attr_name});
	}
	if ($AUTOLOAD =~ /.*::set(_\w+)/ && $self->_accessible($1)) {
		my $attr_name = $1;
		*{$AUTOLOAD} = sub { $_[0]->{$attr_name} = $_[1]; return; };
		$self->{$1} = $value;
		return; 
	} 
	croak "No such method: $AUTOLOAD";
}

# Just for kicks, report an error if we know of one.
sub DESTROY { 
	my ($self) = @_;
	my $error = $self->get_error(); 
	if ($error) { 
		$self->verbose("Net::MAC detected an error: $error"); 
		return(1); 
	} 
} 

# Discover the metadata for this MAC, using hints if necessary
sub _discover { 
	my ($self) = @_; 
	my $mac = $self->get_mac();
	# Check for undefined MAC or invalid characters
	if (!(defined $mac)) { 
		$self->error("discovery of MAC address metadata failed, no MAC address supplied"); 
	} 
	elsif ($mac =~ /[^:\.\-\sa-fA-F0-9]/) {
		$self->error("discovery of MAC address metadata failed, invalid characters in MAC address \"$mac\""); 
	} 
	
	unless ($self->get_delimiter()) { $self->_find_delimiter(); } 
	unless ($self->get_base()) { $self->_find_base(); } 
	unless ($self->get_bit_group()) { $self->_find_bit_group(); } 
	$self->_write_internal_mac(); 
	return(1); 
} 

# Find the delimiter for this MAC address
sub _find_delimiter { 
	my ($self) = @_; 
	my $mac = $self->get_mac();
	if ($mac =~ /(:|\.|\-|\s)/g) { # Found a delimiter 
		$self->set_delimiter($1); 
		return(1); 
	} 
	else { 
		$self->set_delimiter(undef); 
		return(1); 
	} 
	$self->error("internal Net::MAC failure for MAC \"$mac\""); 
	return(0); # Bizarre failure if we get to this line.
} 

# Find the numeric base for this MAC address
sub _find_base { 
	my ($self) = @_;
	my $mac = $self->get_mac();
	if ($mac =~ /[a-fA-F]/) { 
		# It's hexadecimal
		$self->set_base(16); 
		return(1); 
	} 
	my @groups = split(/:|\.|\-|\s/, $mac); 
	my $is_decimal = 0; 
	foreach my $group (@groups) { 
		if (length($group) == 3) { 
			# It's decimal, sanity check it
			$is_decimal = 1; 
			if ($group > 255) { 
				$self->error("invalid decimal MAC \"$mac\""); 
				return(0); 
			}
		} 
	} 
	if ($is_decimal) { 
		$self->set_base(10); 
		return(1); 
	}
	# There are no obvious indicators, so we'll default the value
	$self->_default('base'); 
	return(1); 
} 

# Find the bit grouping for this MAC address 
sub _find_bit_group { 
	my ($self) = @_;
	my $mac = $self->get_mac();
	if ($mac =~ /(:|\.|\-|\s)/g) { # Found a delimiter
		my $delimiter = $1; 
		$delimiter =~ s/(\.|\-|\:)/\\$1/;
		if ($delimiter eq ' ') { $delimiter = '\s'; }
		my @groups = split(/$delimiter/, $mac); 
		if ((@groups > 3) && (@groups % 2)) {
			$self->error("invalid MAC address format: $mac"); 
		} 
		elsif (@groups) {
			use integer;
			my $n = @groups;
			my $t_bg = 48 / $n; 
			if (($t_bg == 8) || ($t_bg == 16)) { 
				$self->set_bit_group($t_bg); 
				return(1); 
			} 
		} 	
	} 
	else { # No delimiter, bit grouping is 48 bits
		# Sanity check the length of the MAC address in characters
		if (length($mac) != 12) { 
			$self->error("invalid MAC format, not 16 characters in MAC \"$mac\""); 
			return(0); 
		}
		else { 
			$self->set_bit_group(48); 
			return(1); 
		}
	}
	# If we get here the MAC is invalid or there's a bug in Net::MAC
	$self->error("invalid MAC address format \"$mac\""); 
} 

# FIXME: unimplemented
# Find whether this MAC address has zero-padded bit groups 
sub _find_zero_padded { 
	my ($self) = @_;
} 

# Write an internal representation of the MAC address. 
# This is mainly useful for conversion between formats.  
sub _write_internal_mac { 
	my ($self) = @_; 
	my $mac = $self->get_mac(); 
	$mac =~ s/(\w)/\l$1/g;
	#my @groups = $self->get_groups();
	my @groups; 
	my $delimiter = $self->get_delimiter(); 
	if ($delimiter) { 
		$delimiter =~ s/(\.|\-|\:)/\\$1/;
		if ($delimiter eq ' ') { $delimiter = '\s'; }
		@groups = split(/$delimiter/, $mac); 
	}
	else { @groups = $mac; } 
	# Hex base
	if ((defined $self->get_base()) && ($self->get_base() == 16)) {
		my $imac = join('', @groups); 
		$self->set_internal_mac($imac); 
		return(1); 
	} 
	else { # Decimal base
		if (@groups == 6) { # Decimal addresses can only have octet grouping
			my @hex_groups; 
			foreach my $group (@groups) { 
				my $hex = sprintf("%02x", $group);
				push(@hex_groups, $hex); 
			} 
			my $imac = join('', @hex_groups); 
			$self->set_internal_mac($imac); 
			return(1); 
		} 
		else { 
			$self->error("unsupported MAC address format \"$mac\""); 
			return(0); 
		} 
	}
	$self->error("internal Net::MAC failure for MAC \"$mac\""); 
	return(0); # FIXME: die() here? 
} 

# Convert a MAC address object into a different format 
sub convert { 
	my ($self, %arg) = @_; 
	my $imac = $self->get_internal_mac(); 
	my @groups; 
	my $bit_group = $arg{'bit_group'} || 8; # FIXME: ?
	my $offset = 0; 
	use integer; 
	my $size = $bit_group / 4;
	no integer; 
	while ($offset < length($imac)) { 
		my $group = substr($imac, $offset, $size);
		push(@groups, $group); 
		$offset += $size; 
	} 

	# Convert to base 10 if necessary
	if ((exists $arg{'base'}) && ($arg{'base'} == 10)) { # Convert to decimal base
		my @dec_groups; 
		foreach my $group (@groups) { 
			my $dec_group = hex($group); 
			push(@dec_groups, $dec_group); 
		}
		@groups = @dec_groups; 
	}
	my $mac_string; 
	if ($arg{'delimiter'} =~ /:|\-|\.|\s/) { 
		#warn "\nconvert delimiter $arg{'delimiter'}\n"; 
		#my $delimiter = $arg{'delimiter'}; 
		#$delimiter =~ s/(:|\-|\.)/\\$1/; 
		$mac_string = join($arg{'delimiter'}, @groups); 
		#warn "\nconvert groups @groups\n"; 
	} 
	else { 
		$mac_string = join('', @groups); 
	}
	# Construct the argument list for the new Net::MAC object
	$arg{'mac'} = $mac_string; 
	foreach my $test (keys %arg) { 
		#warn "\nconvert arg $test is $arg{$test}\n"; 
	}
	my $new_mac = Net::MAC->new(%arg); 
	return($new_mac); 
} 

# Print verbose messages about internal workings of this class
sub verbose { 
	my ($self, $message) = @_;
	if ( (defined($message)) && ($self->{'_verbose'}) ) {
		chomp($message);
		print "$message\n";
	}
}

# carp(), croak(), or ignore errors, depending on the attributes of the object.
# If the object is configured to stay alive despite errors, this method will 
# store the error message in the '_error' attribute of the object, accessible 
# via the get_error() method.  
sub error { 
	my ($self, $message) = @_; 
	if ($self->get_die()) { # die attribute is set to 1
		croak $message; 
	} 
	elsif ($self->get_verbose()) { # die attribute is set to 0
		$self->set_error($message); 
		carp $message; # Be verbose, carp() the message
	} 
	else { # die attribute is set to 0, verbose is set to 0
		$self->set_error($message); # Just store the error
	} 
	return(1); 
}

1; # Necessary for use statement

__END__

=head1 NAME

Net::MAC - Perl extension for representing and manipulating MAC addresses 

=head1 SYNOPSIS

  use Net::MAC;
  my $mac = Net::MAC->new('mac' => '08:20:00:AB:CD:EF'); 

  # Example: convert to a different MAC address format (dotted-decimal)
  my $dec_mac = $mac->convert(
	  'base' => 10, 	# convert from base 16 to base 10
	  'bit_group' => 8, 	# octet grouping
	  'delimiter' => '.' 	# dot-delimited
  ); 

  print $dec_mac->get_mac(), "\n"; # Should print 8.32.0.171.205.239

  # Example: find out whether a MAC is base 16 or base 10
  my $base = $mac->get_base();
  if ($base == 16) { 
	  print $mac->get_mac(), " is in hexadecimal format\n"; 
  } 
  elsif ($base == 10) { 
	  print $mac->get_mac(), " is in decimal format\n"; 
  }
  else { die "This MAC is invalid"; } 

=head1 DESCRIPTION

This is a module that allows you to 

  - store a MAC address in a Perl object
  - find out information about a stored MAC address
  - convert a MAC address into a specified format

There are quite a few different ways that MAC addresses may be represented 
in textual form.  The most common is arguably colon-delimited octets in 
hexadecimal form.  When working with Cisco devices, however, you are more 
likely to encounter addresses that are dot-delimited 16-bit groups in 
hexadecimal form.  In the Windows world, addresses are usually 
dash-delimited octets in hexadecimal form.  MAC addresses in a Sun ethers 
file are usually non-zero-padded, colon-delimited hexadecimal octets.  And 
sometimes, you come across the totally insane dot-delimited octets in 
decimal form (certain Cisco SNMP MIBS actually use this). Hence the need 
for a common way to represent and manipulate MAC addresses in Perl.  

There is a surprising amount of complexity involved in converting MAC 
addresses between types.  This module does not attempt to understand all 
possible ways of representing a MAC address in a string, though most of the 
common ways of representing MAC addresses are supported.  

=head1 METHODS 

=head2 new() method (constructor)

The new() method creates a new Net::MAC object.  Possible arguments are 

  mac		a string representing a MAC address
  base		a number corresponding to the numeric base of the MAC 
		possible values: 10 16
  delimiter	the delimiter in the MAC address string from above 
		possible values: : - . space
  bit_group	the number of bits between each delimiter 
		possible values: 8 16 48
  verbose	write informational messages (useful for debugging)
		possible values: 0 1
  die		die() on invalid MAC address (default is to die on invalid MAC) 
		possible values: 0 1 (default is 1)

When the new() method is called with a 'mac' argument and nothing else, the 
object will attempt to auto-discover metadata like bit grouping, number base, 
delimiter, etc.  If the MAC is in an invalid or unknown format, the object 
will call the croak() function.  If you don't want the object to croak(), 
you can give the new() method a die argument, such as: 

  my $m_obj = Net::MAC->new('mac' => '000adf012345', 'die' => 0); 

There are cases where the auto-discovery will not be able to guess the 
numeric base of a MAC.  If this happens, try giving the new() method 
a hint, like so: 

  # Example: this MAC is actually in decimal-dotted notation, not hex
  my $mac = Net::MAC->new('mac' => '10.0.0.12.14.8', 'base' => 10); 

This is necessary for cases like the one above, where the class has no way 
of knowing that an address is decimal instead of hexadecimal.  

=head2 accessor methods

=head3 get_mac() method 

Returns the MAC address stored in the object.    

=head3 get_base() method 

Returns the numeric base of the MAC address.  There are two possible return 
values: 

  16 	hexadecimal (common)
  10	decimal (uncommon)

=head3 get_delimiter() method 

Returns the delimiter, if any, in the specified MAC address.  A valid 
delimiter matches the following regular expression:  

  /\:|\-|\.|\s/

In other words, either a colon, a dash, a dot, or a space.  If there is no 
delimiter, this method will return the undefined value (undef).  If an 
invalid delimiter is found (like an asterisk or something), the object will 
call the croak() function.  

=head3 get_bit_group() method

Returns the number of bits between the delimiters.  A MAC address is a 48 bit 
address, usually delimited into 8 bit groupings (called octets), i.e. 

  08:20:00:AB:CD:EF

Sometimes, MAC addresses are specified with fewer than 5 delimiters, or even 
no delimiters at all: 

  0820.00ab.cdef	# get_bit_group() returns 16
  082000abcdef		# get_bit_group() returns 48, no delimiters at all

=head2 convert() method 

Convert an already-defined Net::MAC object into a different MAC address 
format.  With this function you can change the delimiter, the bit grouping, 
or the numeric base.  

  # Example: convert to a different MAC address format (dotted-decimal)
  my $new_mac_obj = $existing_mac_obj->convert(
          'base' => 16,         # convert to base 16, if necessary
          'bit_group' => 16,    # 16 bit grouping
          'delimiter' => '.'    # dot-delimited
  );


=head1 BUGS 

=head2 Malformed MAC addresses 

Net::MAC can't handle MAC addresses where whole leading zero octets are 
omitted.  Example: 

  7.122.32.41.5 (should be 0.7.122.32.41.5)

Arguably, that's their problem and not mine, but maybe someday I'll get 
around to supporting that case as well. 

=head2 Case is not preserved 

Net::MAC doesn't reliably preserve case in a MAC address.  I might add a 
flag to the new() and convert() methods to do this.  I might not. 

=head2 Zero-padding is not configurable 

Net::MAC doesn't allow you to specify whether or not bit groups should 
be zero-padded.  It always writes out base 16 addresses as zero-padded.  
Example: 

  You supply '8.32.0.171.205.239' and you want '8:20:0:ab:cd:ef'.  
  Net::MAC gives you '08:20:00:ab:cd:ef' and a kick in the face. 

I'll probably add support for configurable zero-padding.  

=head1 SEE ALSO

Net::MacMap
Net::MAC::Vendor

=head1 AUTHOR

Karl Ward E<lt>karlward@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 Karl Ward E<lt>karlward@cpan.orgE<gt>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

=cut
