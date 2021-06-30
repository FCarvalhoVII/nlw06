import { Request, Response, NextFunction } from 'express'
import { verify } from 'jsonwebtoken'

interface IPayload {
  sub: string
}

export function ensureAuthenticated(
  req: Request, 
  res: Response, 
  next: NextFunction
) {
  const authToken = req.headers.authorization
  
  if(!authToken) {
    return res.status(401).end()
  }

  const token = authToken.split(' ')[1]

  try {
    const { sub } = verify(token, 'ca1765b8168f69c912664d8f1a890669') as IPayload

    req.user_id = sub
    
    return next()
  } catch(err) {
    return res.status(401).end()
  }
}