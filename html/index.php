<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <title>Is my data in the Lowyat Breach?</title>
        
        <link rel="stylesheet" href="styles.css" />
    </head>
    
<body>

<?php
include '/var/www/keys/credentials.php';
require '/var/www/aws-autoloader.php';

date_default_timezone_set('UTC');

use Aws\DynamoDb\Exception\DynamoDbException;
use Aws\DynamoDb\Marshaler;

$sdk = new Aws\Sdk([
    'endpoint'   => 'https://dynamodb.ap-southeast-1.amazonaws.com',
    'region'   => 'ap-southeast-1',
    'version'  => 'latest'
]);

$dynamodb = $sdk->createDynamoDb();
$marshaler = new Marshaler();

$tableName = 'Breaches';
?>

<?php
$print_results = [];

if ($_SERVER["REQUEST_METHOD"] == "POST"){
	if (empty($_POST["icNum"])) {
  		$nameErr = "IC Number is required";

	} 
	else { 	
		$icNum = strip_icNum($_POST["icNum"]); 
               	$key = $marshaler->marshalJson('{ "icNum": "' . $icNum . '" }' );
		$params = ['TableName' => $tableName, 'Key' => $key ];
		try {
    			$result = $dynamodb->getItem($params);
		} 
		catch (DynamoDbException $e) {
			array_push($print_results, "Unexpected Error: Keith's not as good as he thinks he is :)");
		}

		if ( $result["Item"] == null ) {
			array_push($print_results,"<div class =\"container\">");			
			array_push($print_results,"<br> This IC Number is not in the list of hacked accounts: GOOD! <br>"); 
			array_push($print_results,"</div>");
		}
		else {
			array_push($print_results,"<div class =\"container\">");			
			array_push($print_results,"<br><h1> Oh-Oh!!</h1><br> Your IC Number is in the hack<br><br>");			
			array_push($print_results,"IC Number: <b><u>".$result["Item"]["icNum"]["S"]."</b></u> was exposed in the following:");
			array_push($print_results,"</div>");
			
			foreach ($result["Item"]["pwns"]["L"] as $pwn) 
			{
				array_push($print_results,"<div class =\"container\">");
				array_push($print_results,"<br><br>");
				array_push($print_results,"Exposed in: ".$pwn["M"]["name"]["S"]."<br>");
				array_push($print_results,"Data from: ".$pwn["M"]["dataSource"]["S"]."<br>");
				array_push($print_results,"Data Exposed include: <br>");
				foreach ($pwn["M"]["data"]["L"] as $hacked_data) {
					array_push($print_results,"+    ".$hacked_data["S"]."<br>");
				}
				array_push($print_results,"Example data in this breach: ");
				array_push($print_results,"<b>".$pwn["M"]["sampleData"]["S"]."</b><br>");
				array_push($print_results,"Data has been masked to protect your identity--<i>but this is real!</i><br>");
				array_push($print_results,"</div>");

			}
		}
	}
}

function strip_icNum($data) {
   $stripped_data = trim($data);
   $stripped_data = preg_replace("/[^A-Za-z0-9 ]/", '', $stripped_data);
   return $stripped_data;
}
?>

<div class="container">

    <form id="signup" method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">

        <div class="header">
        
            <h3>Is my IC Number in the Lowyat breach?</h3>
            
            <p>Enter your ic number (no spaces, no dashes) <i> e.g. 201109104567 </i></p>
            
        </div>
        
        <div class="sep"></div>

        <div class="inputs">
           
        
            <input type="text" placeholder="icNum" name="icNum" value="<?php echo $icNum;?>"/>
                                   
            <input type="submit" id="submit" value="Check it">
        
        </div>
	
    </form>
</div>

<?php foreach ($print_results as $arr) { echo $arr; } ?>

</body>
</html>

