# DiscussionmembershipResponse

A Discussionmembership Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDiscussionmembershipID** | **number** | The unique ID of the Discussionmembership | [default to undefined]
**fkiDiscussionID** | **number** | The unique ID of the Discussion | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiModulesectionID** | **number** | The unique ID of the Modulesection | [optional] [default to undefined]
**sDiscussionmembershipDescription** | **string** | The Description containing the detail of who the Discussionmembership refers to | [default to undefined]
**dtDiscussionmembershipJoined** | **string** | The joined date of the Discussionmembership | [default to undefined]

## Example

```typescript
import { DiscussionmembershipResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DiscussionmembershipResponse = {
    pkiDiscussionmembershipID,
    fkiDiscussionID,
    fkiUserID,
    fkiUsergroupID,
    fkiModulesectionID,
    sDiscussionmembershipDescription,
    dtDiscussionmembershipJoined,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
