# MongoDB document schemas (for reference, not enforced)

# User document
# {
#   _id: ObjectId,
#   username: str,
#   password: str (hashed),
#   role: 'user' or 'admin'
# }

# Issue document
# {
#   _id: ObjectId,
#   user_id: ObjectId (who submitted),
#   description: str,
#   category: str,
#   photo_filename: str,
#   latitude: float,
#   longitude: float,
#   created_at: datetime,
#   votes: int,
#   suggestions: [ObjectId],
#   plan_of_execution: str (set by admin),
#   status: str
# }

# Vote document
# {
#   _id: ObjectId,
#   user_id: ObjectId,
#   issue_id: ObjectId,
#   created_at: datetime
# }

# Suggestion document
# {
#   _id: ObjectId,
#   user_id: ObjectId,
#   issue_id: ObjectId,
#   suggestion: str,
#   created_at: datetime
# }

# Plan document (optional, or can be a field in Issue)
# {
#   _id: ObjectId,
#   issue_id: ObjectId,
#   plan: str,
#   created_at: datetime,
#   updated_by: ObjectId (admin)
# } 

# Report document
# {
#   _id: ObjectId,
#   reporter_id: ObjectId (user who reported),
#   issue_id: ObjectId (the reported issue),
#   reason: str,
#   created_at: datetime,
#   status: str (e.g., 'pending', 'reviewed', 'dismissed')
# } 