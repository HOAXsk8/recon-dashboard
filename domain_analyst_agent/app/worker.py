import asyncio
import json
import logging
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from app.agent import app as agent_app
from app.database_utils import fetch_all_work, update_analysis

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize a single runner for the worker
session_service = InMemorySessionService()
runner = Runner(agent=agent_app.root_agent, app_name="app", session_service=session_service)

async def process_task(task):
    target_name = task["target"]
    logger.info(f"Analyzing {task['type']}: {target_name}")
    
    prompt = f"Please analyze the following reconnaissance data for '{target_name}':\n\n{json.dumps(task['data'], indent=2)}"
    
    try:
        # Create a new session for each analysis to avoid state bleed
        session_id = f"worker_{target_name.replace('.', '_')}_{int(asyncio.get_event_loop().time())}"
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
            logger.info(f"Analysis completed for {target_name}")
            await update_analysis(
                task, 
                analysis['analysis_summary'], 
                analysis['exploitation_suggestions']
            )
        else:
            logger.error(f"Agent returned unexpected format for {target_name}: {analysis}")
            
    except Exception as e:
        logger.error(f"Error during analysis of {target_name}: {str(e)}")

async def worker_loop():
    logger.info("Domain Analyst Worker started.")
    while True:
        try:
            tasks = await fetch_all_work()
            if not tasks:
                logger.info("No work found. Sleeping...")
                await asyncio.sleep(60)
                continue
                
            logger.info(f"Found {len(tasks)} targets to analyze.")
            for task in tasks:
                await process_task(task)
                
            logger.info("Finished batch. Sleeping for a while before next refresh...")
            await asyncio.sleep(3600) # Sleep for 1 hour after a full pass
            
        except Exception as e:
            logger.error(f"Worker loop error: {str(e)}")
            await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(worker_loop())
