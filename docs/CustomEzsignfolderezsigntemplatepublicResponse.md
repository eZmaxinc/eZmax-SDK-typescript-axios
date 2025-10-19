# CustomEzsignfolderezsigntemplatepublicResponse

An Ezsignfolder Object in the context of an Ezsigntemplatepublic

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**eEzsignfolderStep** | [**FieldEEzsignfolderStep**](FieldEEzsignfolderStep.md) |  | [default to undefined]
**iEzsignfolderSignaturetotal** | **number** | The number of total signatures that were requested in the Ezsignfolder | [default to undefined]
**iEzsignfolderFormfieldtotal** | **number** | The number of total form fields that were requested in the Ezsignfolder | [default to undefined]
**iEzsignfolderSignaturesigned** | **number** | The number of signatures that were signed in the Ezsignfolder. | [default to undefined]
**a_objEzsignfolderezsigntemplatepublicSigner** | [**Array&lt;CustomEzsignfolderezsigntemplatepublicSignerResponse&gt;**](CustomEzsignfolderezsigntemplatepublicSignerResponse.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CustomEzsignfolderezsigntemplatepublicResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignfolderezsigntemplatepublicResponse = {
    pkiEzsignfolderID,
    sEzsignfolderDescription,
    eEzsignfolderStep,
    iEzsignfolderSignaturetotal,
    iEzsignfolderFormfieldtotal,
    iEzsignfolderSignaturesigned,
    a_objEzsignfolderezsigntemplatepublicSigner,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
