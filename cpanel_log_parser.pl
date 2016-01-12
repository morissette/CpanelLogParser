#!/usr/bin/perl
# Tool for parsing Cpanel logs to human readable logs
# http://mattharris.org

use strict;
use Getopt::Long;
use File::Basename;
use English '-no_match_vars';
use Time::Local;
use URI::Escape;
use Date::Parse;
use LWP::Simple;
use Storable;
use JSON;

# Store cpanel parsing definitions
my $defs;

sub get_options {
    my (
        $archive, $accessed, $help,   $ip,         $list,
        $user,    $show,     $format, $subsection
    );
    GetOptions(
        'archive|a'     => \$archive,
        'accessed|k=s'  => \$accessed,
        'no-format|n'   => \$format,
        'section|s=s'   => \$subsection,
        'usage|help|h'  => \$help,
        'ip|i=s'        => \$ip,
        'listips|l=s'   => \$list,
        'user|u=s'      => \$user,
    );
    if ($help) {
        usage();
        exit;
    }
    if (   !defined $user
        && !defined $ip
        && !defined $list
        && !defined $help
        && !defined $accessed )
    {
        usage();
        exit;
    }
    if ( $user || $ip || $accessed ) {
        download_definitions();
        $defs = retrieve '/tmp/cpanel_log.defs';
    }
    print "[*] Searching for known definitions in access logs...\n";
    if ($archive) {
        $show = 1;
    }
    if ($format) {
        $format = 1;
    }
    if ($user) {
        my $regex = '^\S{7,15} (-|proxy) ' . $user . ' .{27} "';
        my @content = get_log( $show, $regex );
        if ($subsection) {
            @content = section( $subsection, @content );
        }
        format_results( $format, @content );
    }
    if ($ip) {
        my $regex = "^$ip (-|proxy) " . '\S+';
        my @content = get_log( $show, $regex );
        format_results( $format, @content );
    }
    if ($accessed) {
        my $regex = "^$accessed (-|proxy) " . '(\S+)';
        my @users = get_users($regex);
        if ( scalar(@users) ) {
            print join "\n", @users;
            print "\n";
        }
        else {
            print "[!] No results found.\n";
        }
    }
    if ($list) {
        my $regex = '^(\S+) - ' . $list;
        my @ips   = get_ips($regex);
        foreach (@ips) {
            print $_ . "\n";
        }
    }
    return;
}

## Display usage ##
sub usage {
    my $dirname = dirname($PROGRAM_NAME);
    my $script  = basename($PROGRAM_NAME);
    if ( $dirname =~ /dev\/fd/xsm ) {
        $script = 'cpanel_log_parser';
    }
    my $helppage = <<"EOF";

Usage: $script [FLAG] OPTION USER/IP  

Available flags:
   -a, --archive     Enable archived cpanel logs
   -n, --no-format   Disable parsing

Available options:
   -i, --ipsearch    Search based on IP
   -u, --user        Search based on user
   -l, --listips     Show IP's that have connected to the cPanel account
   -s, --section     Only show logs for category specified

Available sections:
   ip                Shows ip actions
   mail              Shows mail actions
   db                Shows database actions
   software          Shows installation/uninstallation of software
   acct              Shows account modifications
   conf              Shows configuration changes
   domain            Shows addition/removal of addon, parked and subdomains
   dns               Shows dns actions
   ftp               Shows ftp actions

Examples:
   Find all actions by a user
        $script -u username

   Find all actions by a ip
        $script -i ip

   Find all mail actions related to a user
        $script -s mail -u user

   Find all actions by a user without parsing
        $script -u user -n

   Find all ips that have accessed or attempted to access an account
        $script -l user

EOF
    print $helppage;
    return;
}
## End Usage Sub ##

## Start Error Checking ##
sub sanity_checks {
    my $whoami = ( getpwuid($UID) )[0];
    if ( !-d '/usr/local/cpanel' ) {
        print "\n[!] Cpanel does not appear to be installed on this box.\n\n";
        exit;
    }
    if ( $whoami ne 'root' ) {
        print "\n[!] You must be root to run this script.\n\n";
        exit;
    }
    return;
}
## End Error Checking ##

## Gather Logs Which Contain the Search ##
sub get_log {
    my ( $show, $regex ) = @_;
    my $found = 0;
    my @content;
    if ( defined $show ) {
        if ( !-d '/usr/local/cpanel/logs/archive/' ) {
            print "\n[!] No archive logs available.\n\n";
            exit;
        }
        my @archive_logs =
          glob('/usr/local/cpanel/logs/archive/access_log*.gz');
        foreach my $log (@archive_logs) {
            open my $fh, qw{-|}, "/bin/zcat $log"
              or die "Could not open: $log.\n";
            while (<$fh>) {
                if ( $_ =~ /$regex/sm ) {
                    push @content, $_;
                    $found = 1;
                }
            }
            my $error = close $fh;
        }
    }
    else {
        my $cpanel_log = '/usr/local/cpanel/logs/access_log';
        open my $fh, '<', $cpanel_log or die "Could not open: $cpanel_log.\n";
        while (<$fh>) {
            if ( $_ =~ /$regex/sm ) {
                push @content, $_;
                $found = 1;
            }
        }
        my $error = close $fh;
    }
    if ( $found == 0 ) {
        print "[!] No results found.\n";
        exit;
    }
    return @content;
}
## End Gather ##

## Get Uniq IPs ##
sub get_ips {
    my $regex = shift;
    my ( %ipseen, @ips );
    my $cpanel_log = '/usr/local/cpanel/logs/access_log';
    open my $fh, '<', $cpanel_log or die "Could not open: $cpanel_log.\n";
    while (<$fh>) {
        if ( $_ =~ /$regex/sm ) {
            push @ips, $1;
        }
    }
    close $fh;
    my @unique = grep { !$ipseen{$_}++ } @ips;
    return @unique;
}
## End Get IPs ##

## Get Accounts IP logged into ##
sub get_users {
    my $regex = shift;
    my ( %useen, @users );
    my $cpanel_log = '/usr/local/cpanel/logs/access_log';
    open my $fh, '<', $cpanel_log or die "Could not open: $cpanel_log.\n";
    while (<$fh>) {
        if ( $_ =~ /$regex/sm ) {
            my $user = $2;
            if ( $user =~ /[a-zA-Z0-9]+/ ) {
                push @users, $user;
            }
        }
    }
    close $fh;
    my @unique = grep { !$useen{$_}++ } @users;
    return @unique;
}
## End IP Accounts ##

## Start Sectioning ##
sub section {
    my ( $section, @old_content ) = @_;
    my @keys = grep { $defs->{$_}->{'section'} eq $section } keys %$defs;
    my @content;
    foreach my $line (@old_content) {
        foreach my $key (@keys) {
            my $regex = $defs->{$key}->{'regex'};
            if ( $line =~ /$regex/ ) {
                push @content, $line;
            }
        }
    }
    return @content;
}
## End Sectioning ##

## Start Formatting Subs##
sub format_results {
    my ( $format, @content ) = @_;
    my @formatted;
    my @keys = keys %$defs;
    foreach my $key (@keys) {
        foreach (@content) {
            if ( $_ =~ /$defs->{$key}->{'regex'}/ ) {
                $_ = $key . '-' . $_;
                push @formatted, $_;
            }
        }
    }
    sort_results( $format, @formatted );
    return;
}

sub sort_results {
    my ( $format, @content ) = @_;
    foreach my $line (@content) {
        if ( $line =~
/(\S+)-(\S+) (?:-|proxy) (\S+) \[(\d\d)\/(\d\d)\/(\d\d\d\d):(\d\d):(\d\d):(\d\d) -0000\] "(.*)/
          )
        {
            my (
                $option, $ip,   $user, $month, $day,
                $year,   $hour, $min,  $sec,   $content
            ) = ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 );
            my $epoch =
              timegm( $sec, $min, $hour, $day, ( $month - 1 ), $year );
            unless ($format) {
                $content = parse_content( $option, $content );
            }
            $line = {
                epoch => $epoch,
                ip    => $ip,
                user  => $user,
                msg   => $content,
            };
        }
    }
    my $total_results = @content;
    if ($total_results) {
        foreach my $line ( sort { $a->{epoch} <=> $b->{epoch} } @content ) {
            print scalar( localtime $line->{epoch} ) . ' - '
              . $line->{ip} . ' - '
              . $line->{user} . ' - '
              . $line->{msg} . "\n";
        }
    }
    else {
        print "[!] No results found.\n";
    }
    return;
}

sub parse_content {
    my ( $option, $content ) = @_;
    my $regex  = $defs->{$option}->{'format'};
    my $output = $defs->{$option}->{'trans'};
    if ($regex) {
        if ( $content =~ $regex ) {
            my (@replaces) = ( $content =~ $regex );
            for ( my ($i) = 0 ; $i < scalar(@replaces) ; ++$i ) {
                $output =~ s/\{$i\}/@replaces[$i]/;
            }
            $output = uri_unescape($output);
            return $output;
        }
    }
    return $output;
}
## End Formatting Subs ##

## Get Definitions ##
sub download_definitions {
    print "[*] Downloading cPanel parsing definitions...\n";
    my $status =
      getstore( 'https://raw.githubusercontent.com/morissette/CpanelLogParser/master/cpanel_log.defs',
        '/tmp/cpanel_log.defs' );
    if ( is_error($status) ) {
        print "[!] Unable to retreive cPanel parsing definitions\n";
        exit;
    }
}

sub cleanup_definitions {
    unlink('/tmp/cpanel_log.defs');
}
## End Definitions ##

## Do Stuff ##
sanity_checks;
get_options;
cleanup_definitions;
## All Done ##
