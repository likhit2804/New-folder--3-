from aws_cdk import (
    RemovalPolicy,
    Stack,
    aws_lambda as _lambda,
    aws_sqs as sqs,
    aws_dynamodb as dynamodb,
    aws_apigateway as apigateway,
    Duration  # Duration is already imported
)
from constructs import Construct
import aws_cdk as cdk


class TaIacInfraStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 1️⃣ DynamoDB Table (Existing)
        table = dynamodb.Table(
            self, "TaIacScanResults-2",
            table_name="TaIacScanResults-2",
            partition_key={"name": "scan_id", "type": dynamodb.AttributeType.STRING},
            removal_policy=RemovalPolicy.DESTROY
        )

        # ✨ --- ADDED ---
        # 1b. DynamoDB Cache Table (New)
        cache_table = dynamodb.Table(
            self, "TaThreatIntelCache-2",
            table_name="TaThreatIntelCache-2", # New table for caching
            partition_key={"name": "cache_key", "type": dynamodb.AttributeType.STRING},
            time_to_live_attribute="expires_at", # Enable DynamoDB TTL for cache expiration
            removal_policy=RemovalPolicy.DESTROY # Good for dev, use RETAIN for prod
        )
        # --- END ADDED ---

        # 2️⃣ SQS Queue (Existing)
        queue = sqs.Queue(
            self, "TaIacScanQueue-2",
            queue_name="TaIacScanQueue-2"
        )

        # Lambda Code Asset (Existing)
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

        # 3️⃣ Submitter Lambda (Existing)
        submitter_lambda = _lambda.Function(
            self, "SubmitterLambda-2",
            function_name="TaIacSubmitter-2",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="lambda.submitter_lambda.lambda_handler",
            code=lambda_code_asset,
            environment={
                "QUEUE_URL": queue.queue_url
            }
        )

        # 4️⃣ Worker Lambda (Modified)
        worker_lambda = _lambda.Function(
            self, "WorkerLambda-2",
            function_name="TaIacWorker-2",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="lambda.worker_lambda.lambda_handler",
            code=lambda_code_asset,
            # ✨ --- MODIFIED ---
            # Increased timeout for external API calls in threat_adapters
            timeout=Duration.seconds(30), 
            environment={
                "TABLE_NAME": table.table_name,
                # Added environment variable for the cache table name
                "CACHE_TABLE_NAME": cache_table.table_name 
            }
            # --- END MODIFIED ---
        )

        # 5️⃣ Give Lambdas permissions (Modified)
        queue.grant_send_messages(submitter_lambda)
        queue.grant_consume_messages(worker_lambda)
        table.grant_write_data(worker_lambda)
        
        # ✨ --- ADDED ---
        # Grant worker permissions to read/write from the cache
        cache_table.grant_read_write_data(worker_lambda) 
        # --- END ADDED ---


        # 6️⃣ Connect SQS to Worker Lambda (Existing)
        worker_lambda.add_event_source_mapping(
            "SQSTrigger-2",
            event_source_arn=queue.queue_arn,
            batch_size=1
        )

        # 7️⃣ API Gateway (Modified)
        api = apigateway.LambdaRestApi(
            self, "TaIacAPI-2",
            handler=submitter_lambda,
            proxy=False,
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key"]
            )
        )

        # ✨ --- MODIFIED ---
        # Changed resource to 'scans' (plural) for consistency
        scans = api.root.add_resource("scans") 
        scans.add_method("POST")
        # --- END MODIFIED ---


app = cdk.App()
# Keep your existing stack name
stack = TaIacInfraStack(app, "TaIacInfraStack-2") 
app.synth()
