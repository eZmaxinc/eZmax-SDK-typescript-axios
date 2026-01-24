# EzsigntemplateCopyV1Request

Request for POST /1/object/ezsigntemplate/{pkiEzsigntemplateID}/copy

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_fkiEzsignfoldertypeID** | **Array&lt;number&gt;** |  | [optional] [default to undefined]
**bCopyCompany** | **boolean** | Whether we shall copy the Ezsigntemplate as a company Ezsigntemplate | [optional] [default to undefined]
**bCopyUser** | **boolean** | Whether we shall copy the Ezsigntemplate as a user Ezsigntemplate | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplateCopyV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateCopyV1Request = {
    a_fkiEzsignfoldertypeID,
    bCopyCompany,
    bCopyUser,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
