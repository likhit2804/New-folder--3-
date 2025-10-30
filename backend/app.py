from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_lambda as _lambda,
    aws_sqs as sqs,
    aws_dynamodb as dynamodb,
    aws_apigateway as apigateway,
    aws_events as events,
    aws_events_targets as targets,
    Duration
)
from constructs import Construct
import aws_cdk as cdk

# ✨ --- ADDED ---
import os
from dotenv import load_dotenv

# Load environment variables from .env file at the root of the 'backend' folder
load_dotenv()
# --- END ADDED ---


class TaIacInfraStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 1️⃣ & 1b. DynamoDB Tables (No Change)
        table = dynamodb.Table(
            self, "TaIacScanResults-5",
            table_name="TaIacScanResults-5",
            partition_key={"name": "scan_id", "type": dynamodb.AttributeType.STRING},
            removal_policy=RemovalPolicy.DESTROY
        )
        cache_table = dynamodb.Table(
            self, "TaThreatIntelCache-5",
            table_name="TaThreatIntelCache-5", 
            partition_key={"name": "cache_key", "type": dynamodb.AttributeType.STRING},
            time_to_live_attribute="expires_at", 
            removal_policy=RemovalPolicy.DESTROY 
        )

        # 2️⃣ SQS Queue (No Change)
        # 2️⃣ SQS Queue (MODIFIED)
        queue = sqs.Queue(
            self, "TaIacScanQueue-5",
            queue_name="TaIacScanQueue-5",
            # ✨ --- ADDED: Set timeout LONGER than the worker's 300s timeout ---
            visibility_timeout=Duration.seconds(330) # 5.5 minutes
        )

        # Lambda Code Asset (No Change)
        lambda_code_asset = _lambda.Code.from_asset(
            "y",
            bundling={
                "image": _lambda.Runtime.PYTHON_3_11.bundling_image,
                "command": [
                    "bash",
                    "-c",
                    "pip install -r requirements.txt -t /asset-output && cp -r . /asset-output"
                ],
            },
        )

        # 3️⃣ Submitter Lambda (No Change)
        submitter_lambda = _lambda.Function(
            self, "SubmitterLambda-5",
            function_name="TaIacSubmitter-5",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="lambda.submitter_lambda.lambda_handler",
            code=lambda_code_asset,
            environment={
                "QUEUE_URL": queue.queue_url,
                "TABLE_NAME": table.table_name
            }
        )

        # 4️⃣ Worker Lambda (Modified)
        worker_lambda = _lambda.Function(
            self, "WorkerLambda-5",
            function_name="TaIacWorker-5",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="lambda.worker_lambda.lambda_handler",
            code=lambda_code_asset,
            timeout=Duration.seconds(300), 
            environment={
                "TABLE_NAME": table.table_name,
                "CACHE_TABLE_NAME": cache_table.table_name,
                
                # ✨ --- ADDED: Pass keys from .env to the Lambda ---
                "OTX_API_KEY": os.environ.get("OTX_API_KEY", ""),
                "SHODAN_API_KEY": os.environ.get("SHODAN_API_KEY", ""),
                "ABUSEIPDB_API_KEY": os.environ.get("ABUSEIPDB_API_KEY", "")
                # --- END ADDED ---
            }
        )
        
        # 4b. Health Check Lambda (Modified)
        health_check_lambda = _lambda.Function(
            self, "HealthCheckLambda-5",
            function_name="TaIacHealthChecker-5",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="lambda.health_check_lambda.lambda_handler",
            code=lambda_code_asset,
            timeout=Duration.seconds(60), 
            environment={
                "CACHE_TABLE_NAME": cache_table.table_name,
                
                # ✨ --- MODIFIED: Pass keys from .env to the Lambda ---
                # Removed hardcoded keys
                "OTX_API_KEY": os.environ.get("OTX_API_KEY", ""),
                "SHODAN_API_KEY": os.environ.get("SHODAN_API_KEY", ""),
                "ABUSEIPDB_API_KEY": os.environ.get("ABUSEIPDB_API_KEY", "")
                # --- END MODIFIED ---
            }
        )
        
        # 4c. Scheduled Rule (No Change)
        rule = events.Rule(
            self, "HealthCheckRule-5",
            schedule=events.Schedule.rate(Duration.minutes(15)),
        )
        rule.add_target(targets.LambdaFunction(health_check_lambda))

        # 5️⃣ & 6️⃣ & 7️⃣ (No Change)
        queue.grant_send_messages(submitter_lambda)
        queue.grant_consume_messages(worker_lambda)
        table.grant_write_data(worker_lambda)
        table.grant_read_write_data(submitter_lambda) 
        cache_table.grant_read_write_data(worker_lambda) 
        cache_table.grant_read_write_data(health_check_lambda)
        
        worker_lambda.add_event_source_mapping(
            "SQSTrigger-5",
            event_source_arn=queue.queue_arn,
            batch_size=1
        )

        api = apigateway.LambdaRestApi(
            self, "TaIacAPI-5",
            handler=submitter_lambda,
            proxy=False,
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key"]
            )
        )
        
        scans = api.root.add_resource("scans") 
        scans.add_method("POST")
        scan_status = scans.add_resource("{scan_id}")
        scan_status.add_method("GET")


app = cdk.App()
stack = TaIacInfraStack(app, "TaIacInfraStack-5") 
app.synth()