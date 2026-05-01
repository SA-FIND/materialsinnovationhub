import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// You will need a free Resend.com API key set in your Supabase project secrets
const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY')
const CRON_SECRET = Deno.env.get('CRON_SECRET')

serve(async (req) => {
  try {
    // Only allow execution if the cron secret matches
    const reqSecret = req.headers.get('x-cron-secret')
    if (reqSecret !== CRON_SECRET) {
      return new Response('Unauthorized', { status: 401 })
    }

    // Initialize Supabase Admin client
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '' // We use service role to bypass RLS for this backend job
    )

    // Fetch all incomplete tasks
    const { data: pendingTasks, error: taskError } = await supabaseClient
      .from('tasks')
      .select('description, task_assignees(member_id)')
      .in('status', ['pending', 'in progress'])

    if (taskError) throw taskError

    // Fetch all members
    const { data: members, error: memberError } = await supabaseClient
      .from('members')
      .select('id, name, email')

    if (memberError) throw memberError

    // Group incomplete tasks by member
    const memberTasks = new Map()
    pendingTasks.forEach(task => {
      task.task_assignees.forEach(assignee => {
        const mid = assignee.member_id
        if (!memberTasks.has(mid)) memberTasks.set(mid, [])
        memberTasks.get(mid).push(task.description)
      })
    })

    const emailsToSend = []
    memberTasks.forEach((tasks, mid) => {
      const member = members.find(m => m.id === mid)
      if (member) {
        emailsToSend.push({
          from: 'MIH Tracker <onboarding@resend.dev>', // Update this when you have a custom domain
          to: member.email,
          subject: '⏰ Action Required: Pending MIH Tasks',
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
              <h2>Hi ${member.name},</h2>
              <p>This is your automated Friday reminder! You currently have <strong>${tasks.length}</strong> tasks that need your attention:</p>
              <ul>
                ${tasks.map(t => `<li>${t}</li>`).join('')}
              </ul>
              <p>Please log in to the MIH Tracker and update your progress before the end of the day.</p>
              <br>
              <p>Best,<br>Materials Innovation Hub Team</p>
            </div>
          `
        })
      }
    })

    // Send emails using Resend API
    let emailsSent = 0;
    if (emailsToSend.length > 0 && RESEND_API_KEY) {
      for (const email of emailsToSend) {
        const res = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` },
          body: JSON.stringify(email)
        })
        if (res.ok) emailsSent++
      }
    }

    return new Response(JSON.stringify({ success: true, pendingUsers: memberTasks.size, emailsSent }), { headers: { "Content-Type": "application/json" } })
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { headers: { "Content-Type": "application/json" }, status: 400 })
  }
})
