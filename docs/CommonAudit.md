# CommonAudit

Gives informations about the user that created the object and the last user to have modified it.  If the object was never modified after creation, objAuditdetailModified won\'t be returned. 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objAuditdetailCreated** | [**CommonAuditdetail**](CommonAuditdetail.md) |  | [default to undefined]
**objAuditdetailModified** | [**CommonAuditdetail**](CommonAuditdetail.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CommonAudit } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonAudit = {
    objAuditdetailCreated,
    objAuditdetailModified,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
