# DiscussionmessageResponseCompound

A Discussionmessage Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDiscussionmessageID** | **number** | The unique ID of the Discussionmessage | [default to undefined]
**fkiDiscussionID** | **number** | The unique ID of the Discussion | [default to undefined]
**fkiDiscussionmembershipID** | **number** | The unique ID of the Discussionmembership | [optional] [default to undefined]
**fkiDiscussionmembershipIDActionrequired** | **number** | The unique ID of the Discussionmembership | [optional] [default to undefined]
**eDiscussionmessageStatus** | [**FieldEDiscussionmessageStatus**](FieldEDiscussionmessageStatus.md) |  | [default to undefined]
**tDiscussionmessageContent** | **string** | The content of the Discussionmessage | [default to undefined]
**sDiscussionmessageCreatorname** | **string** | The name the creator of the Discussionmessage. | [default to undefined]
**sDiscussionmessageActionrequiredname** | **string** | The name the Actionrequired of the Discussionmessage. | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]

## Example

```typescript
import { DiscussionmessageResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DiscussionmessageResponseCompound = {
    pkiDiscussionmessageID,
    fkiDiscussionID,
    fkiDiscussionmembershipID,
    fkiDiscussionmembershipIDActionrequired,
    eDiscussionmessageStatus,
    tDiscussionmessageContent,
    sDiscussionmessageCreatorname,
    sDiscussionmessageActionrequiredname,
    objAudit,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
