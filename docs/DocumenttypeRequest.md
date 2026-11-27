# DocumenttypeRequest

A Documenttype Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiDocumenttypeID** | **number** | The unique ID of the Documenttype | [optional] [default to undefined]
**objDocumenttypeName** | [**MultilingualDocumenttypeName**](MultilingualDocumenttypeName.md) |  | [default to undefined]
**eDocumenttypeStep** | [**ComputedEDocumenttypeStep**](ComputedEDocumenttypeStep.md) |  | [default to undefined]
**sDocumenttypeDefaultfilename** | **string** | The default filename for the document type | [default to undefined]
**bDocumenttypeShowagent** | **boolean** | Whether the document type should be shown to the agent | [default to undefined]
**bDocumenttypeIsactive** | **boolean** | Whether the documenttype is active or not | [default to undefined]
**bDocumenttypeSale** | **boolean** | Whether the document type applies to sale transactions | [default to undefined]
**bDocumenttypeRental** | **boolean** | Whether the document type applies to rental transactions | [default to undefined]
**bDocumenttypeReference** | **boolean** | Whether the document type is a reference document | [default to undefined]
**bDocumenttypeMortgagereference** | **boolean** | Whether the document type is a mortgage reference | [default to undefined]
**bDocumenttypeEvaluation** | **boolean** | Whether the document type applies to evaluation transactions | [default to undefined]
**bDocumenttypeConsultation** | **boolean** | Whether the document type applies to consultation transactions | [default to undefined]
**bDocumenttypeOtherservices** | **boolean** | Whether the document type applies to other services | [default to undefined]
**bDocumenttypeForeclosedsale** | **boolean** | Whether the document type applies to foreclosed sale transactions | [default to undefined]
**bDocumenttypeCommercialfunding** | **boolean** | Whether the document type applies to commercial funding transactions | [default to undefined]
**bDocumenttypeCanafe** | **boolean** | Whether the document type applies to Canafe transactions | [default to undefined]
**eDocumenttypeEzcom** | [**FieldEDocumenttypeEzcom**](FieldEDocumenttypeEzcom.md) |  | [optional] [default to undefined]
**eDocumenttypePrivacydefault** | [**FieldEDocumenttypePrivacydefault**](FieldEDocumenttypePrivacydefault.md) |  | [default to undefined]
**eDocumenttypeStatusdefault** | [**FieldEDocumenttypeStatusdefault**](FieldEDocumenttypeStatusdefault.md) |  | [default to undefined]
**eDocumenttypeSalebyowner** | [**FieldEDocumenttypeSalebyowner**](FieldEDocumenttypeSalebyowner.md) |  | [default to undefined]
**eDocumenttypeSaledisplaybyrole** | [**FieldEDocumenttypeSaledisplaybyrole**](FieldEDocumenttypeSaledisplaybyrole.md) |  | [default to undefined]
**eDocumenttypeTransactiontype** | [**FieldEDocumenttypeTransactiontype**](FieldEDocumenttypeTransactiontype.md) |  | [default to undefined]
**eDocumenttypeRepossession** | [**FieldEDocumenttypeRepossession**](FieldEDocumenttypeRepossession.md) |  | [default to undefined]
**a_fkiInscriptiontypeID** | **Array&lt;number&gt;** |  | [default to undefined]

## Example

```typescript
import { DocumenttypeRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DocumenttypeRequest = {
    pkiDocumenttypeID,
    objDocumenttypeName,
    eDocumenttypeStep,
    sDocumenttypeDefaultfilename,
    bDocumenttypeShowagent,
    bDocumenttypeIsactive,
    bDocumenttypeSale,
    bDocumenttypeRental,
    bDocumenttypeReference,
    bDocumenttypeMortgagereference,
    bDocumenttypeEvaluation,
    bDocumenttypeConsultation,
    bDocumenttypeOtherservices,
    bDocumenttypeForeclosedsale,
    bDocumenttypeCommercialfunding,
    bDocumenttypeCanafe,
    eDocumenttypeEzcom,
    eDocumenttypePrivacydefault,
    eDocumenttypeStatusdefault,
    eDocumenttypeSalebyowner,
    eDocumenttypeSaledisplaybyrole,
    eDocumenttypeTransactiontype,
    eDocumenttypeRepossession,
    a_fkiInscriptiontypeID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
