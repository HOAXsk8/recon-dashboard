import asyncio
import json
import logging
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from app.agent import app as agent_app
from app.database_utils import fetch_pending_domains, update_domain_analysis

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize a single runner for the worker
session_service = InMemorySessionService()
runner = Runner(agent=agent_app.root_agent, app_name="app", session_service=session_service)

async def analyze_domain(domain_data):
    domain_name = domain_data.get("domain")
    logger.info(f"Analyzing domain: {domain_name}")
    
    # Prepare data for the agent
    clean_data = {
        "domain": domain_name,
        "infrastructure": domain_data.get("infrastructure", {}),
        "systems": domain_data.get("systems", []),
        "web_applications": domain_data.get("web_applications", []),
        "recon_date": domain_data.get("recon_date")
    }
    
    prompt = f"Please analyze the following reconnaissance data for the domain '{domain_name}':\n\n{json.dumps(clean_data, indent=2)}"
    
    try:
        # Create a new session for each domain analysis to avoid state bleed
        session_id = f"worker_{domain_data['domain']}_{int(asyncio.get_event_loop().time())}"
        await session_service.create_session(app_name="app", user_id="worker", session_id=session_id)
        
        analysis = None
        async for event in runner.run_async(
            user_id="worker",
            session_id=session_id,
            new_message=types.Content(role="user", parts=[types.Part(text=prompt)])
        ):
            if event.output is not None:
                analysis = event.output
            if not analysis and event.actions and event.actions.state_delta and 'analysis' in event.actions.state_delta:
                analysis = event.actions.state_delta['analysis']
        
        if analysis and isinstance(analysis, dict) and 'analysis_summary' in analysis and 'exploitation_suggestions' in analysis:
            logger.info(f"Analysis completed for {domain_name}")
            await update_domain_analysis(
                domain_data["_id"], 
                analysis['analysis_summary'], 
                analysis['exploitation_suggestions']
            )
        else:
            logger.error(f"Agent returned unexpected format for {domain_name}: {analysis}")
            
    except Exception as e:
        logger.error(f"Error during analysis of {domain_name}: {str(e)}")

async def worker_loop():
    logger.info("Domain Analyst Worker started.")
    while True:
        try:
            pending_domains = await fetch_pending_domains()
            if not pending_domains:
                logger.info("No pending domains to analyze. Sleeping...")
                await asyncio.sleep(60) # Sleep for 1 minute
                continue
                
            logger.info(f"Found {len(pending_domains)} domains to analyze.")
            for domain in pending_domains:
                await analyze_domain(domain)
                
            logger.info("Finished batch. Sleeping...")
            await asyncio.sleep(30)
            
        except Exception as e:
            logger.error(f"Worker loop error: {str(e)}")
            await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(worker_loop())
