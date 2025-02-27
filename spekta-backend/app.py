import re
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import requests
from flask import Flask, jsonify, request
import pytz
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BACKEND_API_URL = "http://localhost:5001/posts"

def fetch_posts_from_backend(platform=None):
    """
    Fetch posts from the backend API
    
    Args:
        platform: Optional platform filter
    
    Returns:
        List of post objects
    """
    try:
        params = {}
        if platform:
            params['platform'] = platform
            
        response = requests.get(BACKEND_API_URL, params=params)
        response.raise_for_status()  
        
        return response.json()
    except Exception as e:
        return []

def normalize_hashtags(posts):
    """
    Normalize the hashtag format from the backend
    
    Args:
        posts: List of post objects with hashtags in AWS DynamoDB format
    
    Returns:
        Posts with normalized hashtags
    """
    normalized_posts = []
    
    for post in posts:
        # Handle different hashtag formats
        if 'hashtags' in post:
            # Case 1: AWS DynamoDB format: [{"S": "AI"}, {"S": "EasyWork"}]
            if isinstance(post['hashtags'], list) and len(post['hashtags']) > 0 and isinstance(post['hashtags'][0], dict) and 'S' in post['hashtags'][0]:
                normalized_hashtags = [f"#{item['S'].lower()}" for item in post['hashtags']]
                post_content = ' '.join(normalized_hashtags)  # Create content from hashtags
            # Case 2: Simple string array: ["AI", "EasyWork"]
            elif isinstance(post['hashtags'], list):
                normalized_hashtags = [f"#{tag.lower()}" for tag in post['hashtags'] if tag]
                post_content = ' '.join(normalized_hashtags)  # Create content from hashtags
            else:
                normalized_hashtags = []
                post_content = ''
                
            normalized_post = {
                'content': post_content,
                'createdAt': post.get('createdAt', ''),
                'username': post.get('username', 'Unknown User'),
                'normalized_hashtags': normalized_hashtags,
                'postId': post.get('postId', '')
            }
            
            normalized_posts.append(normalized_post)
    
    return normalized_posts

def extract_hashtags(text):
    """Extract hashtags from post content"""
    if not text or not isinstance(text, str):
        return []
    
    # Find all hashtags in the text
    hashtag_pattern = r'#(\w+)'
    hashtags = re.findall(hashtag_pattern, text)
    return [f'#{tag.lower()}' for tag in hashtags]  # Normalize to lowercase

# In the get_hashtag_trending_periods function, modify the date filtering section:
def get_hashtag_trending_periods(posts, start_date, end_date):
    """
    Find when each hashtag was trending
    
    Args:
        posts: List of normalized post objects
        start_date: Beginning of date range
        end_date: End of date range
    
    Returns:
        Dict with hashtags and their trending date ranges
    """
    if not posts:
        return {}
    
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame(posts)
    
    # Ensure createdAt is datetime
    df['createdAt'] = pd.to_datetime(df['createdAt'])
    
    # Check if createdAt has timezone info and handle it
    sample_dt = df['createdAt'].iloc[0] if not df.empty else None
    
    # If createdAt has timezone and start_date/end_date don't, localize them
    if sample_dt is not None and sample_dt.tzinfo is not None:
        import pytz
        
        # Get the timezone from the sample datetime
        tz = sample_dt.tzinfo
        
        # Check if start_date and end_date need timezone info
        if start_date.tzinfo is None:
            start_date = pytz.utc.localize(start_date)
        if end_date.tzinfo is None:
            end_date = pytz.utc.localize(end_date)
    # If start_date/end_date have timezone but createdAt doesn't, convert to naive
    elif sample_dt is not None and sample_dt.tzinfo is None and (start_date.tzinfo is not None or end_date.tzinfo is not None):
        start_date = start_date.replace(tzinfo=None)
        end_date = end_date.replace(tzinfo=None)
    
    # Filter posts within time window
    date_filtered = df[(df['createdAt'] >= start_date) & (df['createdAt'] <= end_date)]
    
    # Rest of the function remains the same...
    
    if date_filtered.empty:
        return {}
    
    # Group by date
    date_filtered['date'] = date_filtered['createdAt'].dt.date
    dates = sorted(date_filtered['date'].unique())
    
    # Track hashtag counts by date
    hashtag_daily_counts = {}
    
    # Process each day
    for date in dates:
        day_posts = date_filtered[date_filtered['date'] == date]
        day_hashtags = []
        
        # Extract hashtags from all posts for this day
        for idx, row in day_posts.iterrows():
            # If normalized_hashtags exist, use them directly
            if 'normalized_hashtags' in row and isinstance(row['normalized_hashtags'], list):
                day_hashtags.extend(row['normalized_hashtags'])
            # Otherwise extract hashtags from content
            elif 'content' in row:
                tags = extract_hashtags(row['content'])
                day_hashtags.extend(tags)
        
        # Count hashtags for this day
        date_str = date.strftime('%Y-%m-%d')
        
        for tag in set(day_hashtags):
            count = day_hashtags.count(tag)
            if tag not in hashtag_daily_counts:
                hashtag_daily_counts[tag] = {}
            
            hashtag_daily_counts[tag][date_str] = count
    
    # Find trending periods for each hashtag
    trending_periods = {}
    
    for tag, daily_counts in hashtag_daily_counts.items():
        if not daily_counts:
            continue
        
        # Get average count
        avg_count = sum(daily_counts.values()) / len(daily_counts)
        
        # A hashtag is considered "trending" when its usage is at least 50% above average
        trending_threshold = avg_count * 1.5
        
        # Find days when hashtag was trending
        trending_days = [date for date, count in daily_counts.items() if count >= trending_threshold]
        
        if not trending_days:
            # If no day meets the trending threshold, find the peak day
            peak_date = max(daily_counts.items(), key=lambda x: x[1])[0]
            trending_periods[tag] = {
                "trending_period": peak_date,
                "peak_date": peak_date,
                "peak_count": daily_counts[peak_date],
                "avg_count": round(avg_count, 1)
            }
            continue
        
        # Sort the trending days
        trending_days.sort()
        
        # Group consecutive days into periods
        periods = []
        current_period = [trending_days[0], trending_days[0]]
        
        for i in range(1, len(trending_days)):
            current_date = datetime.strptime(trending_days[i], '%Y-%m-%d').date()
            prev_date = datetime.strptime(trending_days[i-1], '%Y-%m-%d').date()
            
            # If dates are consecutive
            if (current_date - prev_date).days <= 2:  # Allow 1-day gaps
                current_period[1] = trending_days[i]
            else:
                periods.append(current_period)
                current_period = [trending_days[i], trending_days[i]]
        
        # Add the last period
        periods.append(current_period)
        
        # Find peak date and count
        peak_date = max(daily_counts.items(), key=lambda x: x[1])[0]
        
        # Format trending periods
        formatted_periods = []
        for period in periods:
            if period[0] == period[1]:
                formatted_periods.append(period[0])
            else:
                formatted_periods.append(f"{period[0]} to {period[1]}")
        
        trending_periods[tag] = {
            "trending_period": " and ".join(formatted_periods),
            "peak_date": peak_date,
            "peak_count": daily_counts[peak_date],
            "avg_count": round(avg_count, 1)
        }
    
    return trending_periods

@app.route('/api/hashtag-trending-periods', methods=['GET'])
def get_trending_periods():
    """API endpoint to get hashtag trending periods"""
    try:
        # Get date range parameters from query string
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        platform = request.args.get('platform')
        
        # Parse dates or use defaults (last 30 days)
        end_date = datetime.now()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        
        start_date = end_date - timedelta(days=30)  # Default: 30 days
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        
        # Fetch posts from backend API
        posts = fetch_posts_from_backend(platform)
        
        # Normalize hashtags
        normalized_posts = normalize_hashtags(posts)
        
        # Get trending periods for all hashtags
        trending_periods = get_hashtag_trending_periods(normalized_posts, start_date, end_date)
        
        # Sort hashtags by peak count (most popular first)
        sorted_hashtags = sorted(
            trending_periods.items(),
            key=lambda x: x[1]['peak_count'], 
            reverse=True
        )
        
        # Format the result
        result = {
            "hashtag_trending_periods": {tag: data for tag, data in sorted_hashtags[:20]},  # Top 20
            "analysis_period": {
                "start_date": start_date.strftime('%Y-%m-%d'),
                "end_date": end_date.strftime('%Y-%m-%d')
            },
            "total_hashtags_analyzed": len(trending_periods),
            "total_posts_analyzed": len(normalized_posts)
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hashtag/<hashtag>/trending-period', methods=['GET'])
def get_single_hashtag_trending_period(hashtag):
    """API endpoint to get trending period for a specific hashtag"""
    try:
        # Get date range parameters from query string
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        platform = request.args.get('platform')
        
        # Parse dates or use defaults (last 90 days)
        end_date = datetime.now()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        
        start_date = end_date - timedelta(days=90)  # Default: 90 days for better trend analysis
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        
        # Fetch posts from backend API
        posts = fetch_posts_from_backend(platform)
        
        # Normalize hashtags
        normalized_posts = normalize_hashtags(posts)
        
        # Format hashtag correctly
        if not hashtag.startswith('#'):
            hashtag = f'#{hashtag}'
        hashtag = hashtag.lower()
        
        # Get trending periods for all hashtags
        trending_periods = get_hashtag_trending_periods(normalized_posts, start_date, end_date)
        
        if hashtag in trending_periods:
            return jsonify({
                "hashtag": hashtag,
                "trending_data": trending_periods[hashtag],
                "analysis_period": {
                    "start_date": start_date.strftime('%Y-%m-%d'),
                    "end_date": end_date.strftime('%Y-%m-%d')
                }
            })
        else:
            return jsonify({
                "hashtag": hashtag,
                "trending_data": None,
                "message": f"Hashtag {hashtag} was not found or did not trend in the specified period"
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hashtag-distribution', methods=['GET'])
def get_hashtag_distribution():
    """API endpoint to get distribution of hashtag usage"""
    try:
        # Get date range parameters from query string
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        platform = request.args.get('platform')
        
        # Parse dates or use defaults (last 30 days)
        end_date = datetime.now()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        
        start_date = end_date - timedelta(days=30)  # Default: 30 days
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        
        # Fetch posts from backend API
        posts = fetch_posts_from_backend(platform)
        
        # Normalize hashtags
        normalized_posts = normalize_hashtags(posts)
        
        # Convert to DataFrame for easier manipulation
        df = pd.DataFrame(normalized_posts)
        
        # Ensure createdAt is datetime
        df['createdAt'] = pd.to_datetime(df['createdAt'])
        
        # Filter posts within time window
        date_filtered = df[(df['createdAt'] >= start_date) & (df['createdAt'] <= end_date)]
        
        if date_filtered.empty:
            return jsonify({
                "message": "No posts found in the specified time period",
                "analysis_period": {
                    "start_date": start_date.strftime('%Y-%m-%d'),
                    "end_date": end_date.strftime('%Y-%m-%d')
                }
            })
        
        # Extract all hashtags
        all_hashtags = []
        for idx, row in date_filtered.iterrows():
            if 'normalized_hashtags' in row and isinstance(row['normalized_hashtags'], list):
                all_hashtags.extend(row['normalized_hashtags'])
            elif 'content' in row:
                tags = extract_hashtags(row['content'])
                all_hashtags.extend(tags)
        
        # Count each hashtag
        hashtag_counts = {}
        for tag in all_hashtags:
            if tag in hashtag_counts:
                hashtag_counts[tag] += 1
            else:
                hashtag_counts[tag] = 1
        
        # Sort hashtags by count
        sorted_hashtags = sorted(
            hashtag_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Format the result
        result = {
            "hashtag_distribution": [
                {"hashtag": tag, "count": count} for tag, count in sorted_hashtags[:50]  # Top 50
            ],
            "analysis_period": {
                "start_date": start_date.strftime('%Y-%m-%d'),
                "end_date": end_date.strftime('%Y-%m-%d')
            },
            "total_hashtags_found": len(hashtag_counts),
            "total_posts_analyzed": len(date_filtered)
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    # Get current date for initial calculation
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)

    
    # Fetch initial data and print some stats
    posts = fetch_posts_from_backend()
    normalized_posts = normalize_hashtags(posts)

    trending_periods = get_hashtag_trending_periods(normalized_posts, start_date, end_date)
    for tag, data in sorted(trending_periods.items(), key=lambda x: x[1]['peak_count'], reverse=True)[:10]:
        print(f"{tag}: Trending during {data['trending_period']}")
        print(f"  Peak on {data['peak_date']} with {data['peak_count']} mentions (avg: {data['avg_count']})")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5002, debug=True)