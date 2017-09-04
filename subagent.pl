#!/usr/bin/perl

use NetSNMP::agent (':all');
use NetSNMP::ASN;
use NetSNMP::OID;
$| = 1; #disable the output buffering
sub hello_handler
{
	my ($handler, $registration_info, $request_info, $requests) = @_;
	my $request;
	my $string_value = "requested OID is out of range";
	for($request = $requests; $request; $request = $request->next()) 
	{
		my $oid = $request->getOID();
		my @oidarray = split/[.]/,$oid;
		my $lastoid = $oidarray[-1];
		if ($request_info->getMode() == MODE_GET)
		{
			if ($oid == new NetSNMP::OID("1.3.6.1.4.1.4171.40.1")) 
			{
				$request->setValue(ASN_COUNTER,time);
			}
			if ($oid > new NetSNMP::OID("1.3.6.1.4.1.4171.40.1"))
			{
				my @data = `cat /usr/share/snmp/counters.conf`;
				my $lastoid = $lastoid - 2;
				my @counter = split(',',$data[$lastoid]);
				my $value = $counter[1];
				my $result = $value*time;
				
				if($result > (2**32))
				{
					$result = $result & 0x00000000ffffffff;
					$request->setValue(ASN_COUNTER,$result);	
				}				
				else
				{
					$request->setValue(ASN_COUNTER,$result);
				}
				@data=();
			}
		}
	}
}
my $agent = new NetSNMP::agent();
$agent->register("lohit", "1.3.6.1.4.1.4171.40", \&hello_handler);
