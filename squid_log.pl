#!/usr/bin/env perl 

=pod

=head1 Using the script for create parse squid log (traffic by date, username and IP address)
#============================================================================================
#
#         FILE: squid_log.pl
#
#        USAGE: ./squid_log.pl <DATE> <USERNAME>  
#
#  DESCRIPTION: Script for create parse squid log (traffic by date, username and IP address) 
#
#      OPTIONS: ---
# REQUIREMENTS: Perl v5.14+, Compress::Zlib
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: Vladislav Sapunov. 
# ORGANIZATION: 
#      VERSION: 1.0
#      CREATED: 23.12.2024 15:35:04
#     REVISION: ---
#============================================================================================
=cut

use strict;
use warnings;
use v5.14;
use utf8;
use POSIX 'strftime';
use Compress::Zlib;

my $squidLogsDir = "/home/admin/perl/squidlog";

#my $date = "2024-12-06";
#my $userName = 'IOUser@DOMAIN.LOC';

my $date = $ARGV[0];

#my $userName = lc($ARGV[1]);
my $userName = $ARGV[1];

&usage() if !defined( $ARGV[0] and $ARGV[1] );

my $userIP;

my %userIPSum = ();
my %sites;
my $sumBytes = 0;

sub parse_log() {

    opendir( DIR, $squidLogsDir );
    my @logFiles = grep { $_ =~ m/access/ } readdir(DIR);
    closedir(DIR);

    foreach my $file (@logFiles) {

        #if (($file =~ m/.log$/) and ($file =~ m/.log.\d$/)) {
        if ($file =~ m/.log$/) {
        	open( FHR, '<', "$squidLogsDir/$file" );
		}
		elsif ($file =~ m/\d$/) {
			open( FHR, '<', "$squidLogsDir/$file" );
		}
		elsif ($file =~ m/.gz$/) {
			open (FHR, "gunzip -c $squidLogsDir/$file|");
		}
		else {
			die "Couldn't Open file $file" . "$!\n";
		}

        while ( my $logStr = <FHR> ) {
			
			if ($logStr !~ m/$date/) {
				next;
			}
            
			#if ($logStr =~ m/$userName/) { say "$logStr"; }
            if ( $logStr !~ m/$userName/ ) {
                next;
            }

#2024-12-06 09:27:42.693 10.212.12.28 IOUser@DOMAIN.LOC   1547 TCP_TUNNEL/200 4106 CONNECT help.kontur.com:443
#               	  date                  ip       username     duration reqStat httpStat sqReqStat bytes method  url
            if ( $logStr !~ m/^([\d\-]+ [\d\.\:]+)\s+([\d\.]+)\s+([\w\@\.]+)\s+(\d+)\s+(\w+)\/(\d+)\s+(\d+)\s+(\w+)\s+(\S+)$/) {
                next;
            }

#say $1; say $2; say $3; say $4; say $5; say $6; say $7; say $8; say $9;
#my $dateAndTime = $1; my $clientIP = $2; my $clientUserName = lc($3); #my $responseTime= $4; my $squidRequestStatus = $5; #my $httpStatusCode = $6;
#my $bytes = $7; my $requestMethod = $8; my $requestURL = $9;
            my $clientIP           = $2;
            my $clientUserName     = $3;
            my $squidRequestStatus = $5;
            my $bytes              = $7;
            my $requestURL         = $9;

            if ( $clientUserName !~ /$userName/ ) {
                next;
            }

            if ( $squidRequestStatus =~ m/DENIED/ ) {
                next;
            }

            $sumBytes += int($bytes);
            $userIPSum{"$clientUserName $clientIP"} += int($bytes);

            $requestURL =~ m/(?:(?:http|ftp)\:\/\/)*([\w\.\-]+)(?:\/|\:|$)/;
            $sites{$1} += int($bytes);
        }

        close FHR;
    }
}

sub gen_report() {
    say "=" x 70;
    say "\nUser traffic by IP address:";
    foreach ( keys %userIPSum ) {
        say "$date\t$_\t$userIPSum{$_}\n";
        say "=" x 70;
    }

    my @keys = sort { int( $sites{$b} ) <=> int( $sites{$a} ) } keys %sites;
    foreach (@keys) {
        printf "%50s\t %10s\n", "$_", "$sites{$_}";
    }
    say "=" x 70;
    say "\nDate:\t\t$date\nUser:\t\t$userName\nTotal bytes:\t$sumBytes\n";
    say "=" x 70;
}

sub save_report() {
	my $timestamp = strftime('%Y-%m-%dT%H-%M-%S', localtime());
	# Destination File
	my $outFile = "report" . "_" . "$userName" . "_" . "$date" . "_" . "$timestamp" . ".txt";

	# Open result outFile for writing
	open( FHW, '>>', $outFile ) or die "Couldn't Open file $outFile" . "$!\n";

    say FHW "=" x 70;
    say FHW "\nUser traffic by IP address:";
    foreach ( keys %userIPSum ) {
        say FHW "$date\t$_\t$userIPSum{$_}\n";
        say FHW "=" x 70;
    }

    my @keys = sort { int( $sites{$b} ) <=> int( $sites{$a} ) } keys %sites;
    foreach (@keys) {
        printf FHW "%50s\t %10s\n", "$_", "$sites{$_}";
    }
    say FHW "=" x 70;
    say FHW "\nDate:\t\t$date\nUser:\t\t$userName\nTotal bytes:\t$sumBytes\n";
    say FHW "=" x 70;

	# Closing the filehandles
	close(FHW) or die "$!\n";

	say "Report TXT file of $userName by $date : $outFile created successfully!\n";
	exit;
}

sub usage {
    say "\n" . 
		"Usage: squid_log.pl <DATE> <USERNAME>\n" .
		"Example: squid_log.pl 2024-12-06 IOUser\@DOMAIN.LOC\n\n" .
		"\n";
    exit;
}

&parse_log();
&gen_report();
&save_report();

