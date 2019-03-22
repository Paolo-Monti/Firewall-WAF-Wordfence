<?php
namespace Firewall;

require( 'library/iptables.class.php' );

use \PDO;

// Seconds in one minute * minutes in one hour * hours in a day = 60 * 60 * 24 = 86400
define( '_ONE_DAY_IN_UNIX_', 86400 );

class WAF
{
    const 
       // Options
       op_simulation            = 'simulation',
       op_debug                 = 'debug',
       op_block_count           = 'block_count',
       op_interval              = 'interval',
       op_chain                 = 'chain',
       op_whitelist             = 'whitelist',
       op_iptables              = 'iptables',
       op_waftable              = 'wordfence_table',
       op_log_name              = 'log',
       // Default values
       default_ini_file_name    = 'waf.ini',
       default_iptables         = '/sbin/iptables',
       default_whitelist_name   = 'whitelist',
       default_wordfence_chain  = 'Wordfence',
       default_wordfence_table  = 'wfBlockedIPLog',
       default_log_name         = '', // i.e. no log
       default_block_count      = 10,
       default_interval         = 10;
    
    private $db_name,           // Name of Wordpress database
            $db_user,           // User name for Wordpress database
            $db_password,       // Password for Wordpress database
            $db_table_prefix,   // Table prefix used in Wordpress database
            $pdo,               // PDO object
            $whitelist,         // Content of the whitelist           
            $wp_config_file,    // File name of the Wordpress configuration file
            $ini_options,       // Content of the configuration file for the class
            $iptables,          // Iptables class instance
            $wordfence_table,   // Name of the Wordfence table inside Wordpress database
            $debug,             // Debug option
            $simulation,        // Simulation option
            $log_name;          // Name of the log file
    
    public  $interval,          // Filter. Number of days to consider before the current date
            $block_count;       // Filter. Number of times an Ip has been blocked
    
    /*************************** PRIVATE METHODS ****************************/
                
    /**
    * Extract data using a regular expression    
    *
    * @param string $regex
    * @param string $subject
    * @return string
    */
    private function extract_data( $regex, $subject )
    {
        preg_match( $regex, $subject, $matches );
        return empty( $matches[1] ) ? '' : $matches[1];
    } // extract_data
    
    /**
    * Return a record value in a safe way
    *
    * @param array $record
    * @param string $index
    * @return mixed
    */
    private function get_record_val( $record, $index )
    {
        return empty( $record[$index] ) ? null : $record[$index];
    } // get_record_val
    
    /**
    * Return in a safe way an option read from the configuration file
    * 
    * @param string $index
    * @param mixed $default
    * @return mixed
    */
    private function get_option( $index, $default = null )
    {
        return empty( $this->ini_options[$index] ) ? $default : trim( $this->ini_options[$index] );
    } // get_option
    
    /**
    * Check if an option read from the configuration file is enabled or not
    * 
    * @param string $index
    * @return boolean
    */
    private function is_option_on( $index, $default = false )
    {
        return filter_var( trim( $this->get_option( $index, $default ) ), FILTER_VALIDATE_BOOLEAN );
    } // is_option_on
    
    /**
    * Append a string to the log file
    *
    * @param string $data
    */
    private function append_to_log( $data )
    {
        if ( empty( $this->log_name ) ) return;
        $message = sprintf( "[%s] %s\n", date( 'd-m-Y H:i' ), $data );
        file_put_contents( $this->log_name, $message, FILE_APPEND | LOCK_EX );
    } // append_to_log
    
    /**
    * Return some record data as a formatted string.
    * Mainly used for simulation/debugging/logging purpose.
    *
    * @param array $record
    * @return string
    */
    private function format_record_data( $record )
    {
        return sprintf( "IP: %s\t - Reason: %-15s - Blocked (times): %-10d - Country: %s",
                        $this->get_ip_from_record( $record ),
                        $this->get_record_val( $record, 'blockType' ),
                        $this->get_record_val( $record, 'blockCount' ),
                        $this->get_record_val( $record, 'countryCode' )
                      );
    } // format_record_data
    
    /**
    * Return a number of days: current date in Unix minus the number of days
    * set inside the class constructor
    *
    * @return int
    */
    private function get_unix_day()
    {
        return floor( ( time() / _ONE_DAY_IN_UNIX_ ) - $this->interval );
    } // get_unix_day
    
    /**
    * Check if the file name supplied includes a directory. If not, returns
    * the file name prepended with the current directory, otherwise it returns
    * the original path
    *
    * @param string $path
    * @return string
    */
    private function get_full_path( $path )
    {
        $result = $path;
        if ( !empty( $result ) )
        {
            if ( '.' == pathinfo( $path, PATHINFO_DIRNAME ) ) {
               $result = __DIR__ . DIRECTORY_SEPARATOR . $result;
            }
        }
        return $result;
    } // get_full_path
    
    /**
    * Create the chain inside iptables and add it to the INPUT chain
    *
    * @return void
    */
    private function create_chain()
    {
       if ( !$this->iptables->create_chain( $this->chain ) ) {
          throw new \Iptables\IptablesException( 'Could not create the chain ' . $this->chain );
       }
       if ( !$this->iptables->add_chain_to_chain( $this->chain, 'INPUT' ) ) {
          throw new \Iptables\IptablesException( 'Could not create the chain ' . $this->chain . ' inside the INPUT chain' );
       }
    } // create_chain
    
    /*************************** PUBLIC METHODS ****************************/
    
    /**
    * Class constructor
    *
    * @param string $wp_config_file
    * @param string $ini_file_name
    */
    public function __construct( $wp_config_file, $ini_file = self::default_ini_file_name )
    {
        if ( !is_readable( $wp_config_file ) )
            throw new Exception( "The file '$wp_config_file' does not exist or could not be read" );
            
        $this->wp_config_file = $wp_config_file;
        
        // Read the configuration file and initialize internal variables
        $file = $this->get_full_path( $ini_file );
        
        $this->ini_options      = parse_ini_file( $file );
        $this->interval         = $this->get_option( self::op_interval, self::default_interval );
        $this->chain            = $this->get_option( self::op_chain, self::default_wordfence_chain );        
        $this->block_count      = $this->get_option( self::op_block_count, self::default_block_count );
        $this->wordfence_table  = $this->get_option( self::op_waftable, self::default_wordfence_table );
        $this->debug            = $this->is_option_on( self::op_debug, false );
        $this->simulation       = $this->is_option_on( self::op_simulation, false );
        $this->log_name         = $this->get_full_path( $this->get_option( self::op_log_name, self::default_log_name ) );
        $file                   = $this->get_full_path( self::op_whitelist, self::default_whitelist_name );        
        
        // Read the whitelist        
        $this->whitelist = file_get_contents( $file );
        if ( $this->debug ) {
           printf("Whitelist file name: %s\nContent: %s\n", $file, $this->whitelist );
        }
         
        // Set the instance for Iptables command
        $this->iptables = new \Iptables\Iptables( $this->get_option( self::op_iptables, self::default_iptables ) );
        $this->iptables->cmd->set_debug_mode( $this->debug );
        
        // Read the Wordpress configuration file
        $file = file_get_contents( $wp_config_file );
        
        // Extract database name
        $regex = '/DB_NAME.*,\s*[\'"](.*\b)/i';
        $this->db_name = $this->extract_data( $regex, $file );
        
        // Extract database user
        $regex = '/DB_USER.*,\s*[\'"](.*\b)/i';
        $this->db_user = $this->extract_data( $regex, $file );
        
        // Extract database password
        $regex = '/DB_PASSWORD.*,\s*[\'"](.*\b)/i';
        $this->db_password = $this->extract_data( $regex, $file );
        
        // Extract database table prefix
        $regex = '/table_prefix\s*=\s*[\'"](.*\b)/i';
        $this->db_table_prefix = $this->extract_data( $regex, $file );
        
        $this->create_chain();
        $this->db_connect();
    } // constructor
    
    /**
    * Connect to the Wordpress database
    * 
    * @return void
    */
    public function db_connect()
    {
       // Create DB connection
       $dsn = 'mysql:dbname='.$this->db_name.';host=127.0.0.1;charset=UTF8';
       $options = array(PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES \'UTF8\'',
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION);
       $this->pdo = new PDO( $dsn, $this->db_user, $this->db_password, $options );
    } // db_connect
    
    /**
    * Retrieve data from the Wordfence table where blocked IPs are stored
    * 
    * @return array
    */
    public function get_firewall_blocks()
    {
        $result = array();
        if ( $this->pdo ) {
            $date = $this->get_unix_day();
            $sql = sprintf('select * from %s where unixday >= %d and blockCount >= %d', $this->db_table_prefix . $this->wordfence_table,
                            $date, $this->block_count );
            if ( $this->debug ) {
                printf( "Unix date: %d\nQuery: %s\n", $date, $sql );
            }
            foreach ( $this->pdo->query( $sql, PDO::FETCH_ASSOC ) as $row ) {
                $result[] = $row;
            }
        }
        return $result;
    } // get_firewall_blocks
    
    /**
    * Output the IPs blocked.
    * Mainly used for simulation/debugging purpose.
    * 
    * @return void
    */
    public function print_blocked_ips()
    {
        $result = $this->get_firewall_blocks();
        printf( "%s\n", $this->wp_config_file );
        foreach( $result as $record ) {
            printf("\t%s\n", $this->format_record_data( $record ) );
        }
    } // print_blocked_ips
    
    /**
    * Return the IP from an already retrieved database record
    * 
    * @param array $record
    * @return string|null
    */
    public function get_ip_from_record( $record )
    {
        $ip = $this->get_record_val( $record, 'IP' );
        return empty( $ip ) ? null : preg_replace( '/^::ffff:/', '', inet_ntop( $ip ) );
    } // get_ip_from_record
    
    /**
    * Return the date from an already retrieved database record
    * 
    * @param array $record
    * @return string|null
    */
    public function get_date_from_record( $record )
    {
        $unixday = $this->get_record_val( $record, 'unixday' );
        if ( empty( $unixday ) ) {
            return null;
        } else {
            $date = new DateTime( '1970-01-01' );
            $days = sprintf( 'P%dD', $unixday );
            $date->add( new DateInterval( $days ) );
            return $date->format( 'Y-m-d' );
        }
    } // get_date_from_record
    
    /**
    * Check if the IP is whitelisted
    * 
    * @param string $ip
    * @return boolean
    */
    public function is_ip_in_whitelist( $ip )
    {
        return empty( $this->whitelist ) ? false : false !== strpos( $this->whitelist, trim( $ip ) );
    } // is_ip_in_whitelist

    /**
    * Block an IP.
    * The IP will be inserted into the "Wordfence" chain set inside the constructor
    *
    * @param string $ip
    * @param array $record
    * @return void
    */
    public function block_ip( $ip, $record = null )
    {
        if ( $this->is_ip_in_whitelist( $ip ) ) return;
        
        if ( $this->iptables->block_ip_in_chain( $ip, $this->chain ) ) {            
            if ( empty( $record ) ) {
                $this->append_to_log( 'Blocked IP: ' . $ip );
            } else {
                $this->append_to_log( $this->format_record_data( $record ) );
            }
        }
    } // block_ip

    /**
    * Block a list of IPs inserting them into the "Wordfence" chain set inside the constructor
    *
    * @return void
    */
    public function block_all_ip()
    {
        if ( $this->simulation ) {
            $this->print_blocked_ips();
	} else {
            $result = $this->get_firewall_blocks();
            foreach ( $result as $record ) {
                $this->block_ip( $this->get_ip_from_record( $record ), $record );
            }
        }
    } // block_all_ip

} // class WAF
?>
