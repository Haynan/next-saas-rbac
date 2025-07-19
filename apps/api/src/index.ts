import { ability } from '@saas/auth'

const userCanInviteSomeoneElse = ability.can('invite', 'User')
const userCanDeleteSomeoneElse = ability.can('delete', 'User')

const userCannotDeleteSomeoneElse = ability.cannot('delete', 'User')

console.log('User can invite someone else:', userCanInviteSomeoneElse)
console.log('User can delete someone else:', userCanDeleteSomeoneElse)
console.log('User cannot delete someone else:', userCannotDeleteSomeoneElse)
