# EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload

Payload for DELETE /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bEzsigntemplatepackageNeedvalidation** | **boolean** | Whether the Ezsignbulksend was automatically modified and needs a manual validation | [default to undefined]
**bEzsignbulksendNeedvalidation** | **boolean** | Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation | [default to undefined]

## Example

```typescript
import { EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload = {
    bEzsigntemplatepackageNeedvalidation,
    bEzsignbulksendNeedvalidation,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
