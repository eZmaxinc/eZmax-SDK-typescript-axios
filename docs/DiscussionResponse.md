# DiscussionResponse

A Discussion Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDiscussionID** | **number** | The unique ID of the Discussion | [default to undefined]
**sDiscussionDescription** | **string** | The description of the Discussion | [default to undefined]
**bDiscussionClosed** | **boolean** | Whether if it\&#39;s an closed | [default to undefined]
**dtDiscussionLastread** | **string** | The date the Discussion was last read | [optional] [default to undefined]
**iDiscussionmessageCount** | **number** | The count of Attachment. | [default to undefined]
**iDiscussionmessageCountunread** | **number** | The count of Attachment. | [default to undefined]
**objDiscussionconfiguration** | [**CustomDiscussionconfigurationResponse**](CustomDiscussionconfigurationResponse.md) |  | [optional] [default to undefined]

## Example

```typescript
import { DiscussionResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DiscussionResponse = {
    pkiDiscussionID,
    sDiscussionDescription,
    bDiscussionClosed,
    dtDiscussionLastread,
    iDiscussionmessageCount,
    iDiscussionmessageCountunread,
    objDiscussionconfiguration,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
