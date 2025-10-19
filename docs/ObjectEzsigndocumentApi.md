# ObjectEzsigndocumentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigndocumentApplyEzsigntemplateV1**](#ezsigndocumentapplyezsigntemplatev1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/applyezsigntemplate | Apply an Ezsigntemplate to the Ezsigndocument|
|[**ezsigndocumentApplyEzsigntemplateV2**](#ezsigndocumentapplyezsigntemplatev2) | **POST** /2/object/ezsigndocument/{pkiEzsigndocumentID}/applyEzsigntemplate | Apply an Ezsigntemplate to the Ezsigndocument|
|[**ezsigndocumentApplyEzsigntemplateglobalV1**](#ezsigndocumentapplyezsigntemplateglobalv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/applyEzsigntemplateglobal | Apply an Ezsigntemplateglobal to the Ezsigndocument|
|[**ezsigndocumentCreateEzsignelementsPositionedByWordV1**](#ezsigndocumentcreateezsignelementspositionedbywordv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/createEzsignelementsPositionedByWord | Create multiple Ezsignsignatures/Ezsignformfieldgroups|
|[**ezsigndocumentCreateEzsignelementsPositionedByWordV2**](#ezsigndocumentcreateezsignelementspositionedbywordv2) | **POST** /2/object/ezsigndocument/{pkiEzsigndocumentID}/createEzsignelementsPositionedByWord | Create multiple Ezsignsignatures/Ezsignformfieldgroups|
|[**ezsigndocumentCreateObjectV1**](#ezsigndocumentcreateobjectv1) | **POST** /1/object/ezsigndocument | Create a new Ezsigndocument|
|[**ezsigndocumentCreateObjectV2**](#ezsigndocumentcreateobjectv2) | **POST** /2/object/ezsigndocument | Create a new Ezsigndocument|
|[**ezsigndocumentCreateObjectV3**](#ezsigndocumentcreateobjectv3) | **POST** /3/object/ezsigndocument | Create a new Ezsigndocument|
|[**ezsigndocumentDeclineToSignV1**](#ezsigndocumentdeclinetosignv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/declineToSign | Decline to sign|
|[**ezsigndocumentDeleteObjectV1**](#ezsigndocumentdeleteobjectv1) | **DELETE** /1/object/ezsigndocument/{pkiEzsigndocumentID} | Delete an existing Ezsigndocument|
|[**ezsigndocumentEditEzsignannotationsV1**](#ezsigndocumenteditezsignannotationsv1) | **PUT** /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignannotations | Edit multiple Ezsignannotations|
|[**ezsigndocumentEditEzsignformfieldgroupsV1**](#ezsigndocumenteditezsignformfieldgroupsv1) | **PUT** /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignformfieldgroups | Edit multiple Ezsignformfieldgroups|
|[**ezsigndocumentEditEzsignsignaturesV1**](#ezsigndocumenteditezsignsignaturesv1) | **PUT** /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignsignatures | Edit multiple Ezsignsignatures|
|[**ezsigndocumentEditEzsignsignaturesV2**](#ezsigndocumenteditezsignsignaturesv2) | **PUT** /2/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignsignatures | Edit multiple Ezsignsignatures|
|[**ezsigndocumentEditObjectV1**](#ezsigndocumenteditobjectv1) | **PUT** /1/object/ezsigndocument/{pkiEzsigndocumentID} | Edit an existing Ezsigndocument|
|[**ezsigndocumentEndPrematurelyV1**](#ezsigndocumentendprematurelyv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/endPrematurely | End prematurely|
|[**ezsigndocumentExtractTextV1**](#ezsigndocumentextracttextv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/extractText | Extract text from Ezsigndocument area|
|[**ezsigndocumentFlattenV1**](#ezsigndocumentflattenv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/flatten | Flatten|
|[**ezsigndocumentGetActionableElementsV1**](#ezsigndocumentgetactionableelementsv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElements | Retrieve actionable elements for the Ezsigndocument|
|[**ezsigndocumentGetActionableElementsV2**](#ezsigndocumentgetactionableelementsv2) | **GET** /2/object/ezsigndocument/{pkiEzsigndocumentID}/getActionableElements | Retrieve actionable elements for the Ezsigndocument|
|[**ezsigndocumentGetAttachmentsV1**](#ezsigndocumentgetattachmentsv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getAttachments | Retrieve Ezsigndocument\&#39;s Attachments|
|[**ezsigndocumentGetCompletedElementsV1**](#ezsigndocumentgetcompletedelementsv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getCompletedElements | Retrieve completed elements for the Ezsigndocument|
|[**ezsigndocumentGetCompletedElementsV2**](#ezsigndocumentgetcompletedelementsv2) | **GET** /2/object/ezsigndocument/{pkiEzsigndocumentID}/getCompletedElements | Retrieve completed elements for the Ezsigndocument|
|[**ezsigndocumentGetDownloadUrlV1**](#ezsigndocumentgetdownloadurlv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getDownloadUrl/{eDocumentType} | Retrieve a URL to download documents|
|[**ezsigndocumentGetEzsignannotationsV1**](#ezsigndocumentgetezsignannotationsv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignannotations | Retrieve an existing Ezsigndocument\&#39;s Ezsignannotations|
|[**ezsigndocumentGetEzsigndiscussionsV1**](#ezsigndocumentgetezsigndiscussionsv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsigndiscussions | Retrieve an existing Ezsigndocument\&#39;s Ezsigndiscussions|
|[**ezsigndocumentGetEzsignformfieldgroupsV1**](#ezsigndocumentgetezsignformfieldgroupsv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignformfieldgroups | Retrieve an existing Ezsigndocument\&#39;s Ezsignformfieldgroups|
|[**ezsigndocumentGetEzsignpagesV1**](#ezsigndocumentgetezsignpagesv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignpages | Retrieve an existing Ezsigndocument\&#39;s Ezsignpages|
|[**ezsigndocumentGetEzsignsignaturesAutomaticV1**](#ezsigndocumentgetezsignsignaturesautomaticv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignsignaturesAutomatic | Retrieve an existing Ezsigndocument\&#39;s automatic Ezsignsignatures|
|[**ezsigndocumentGetEzsignsignaturesV1**](#ezsigndocumentgetezsignsignaturesv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignsignatures | Retrieve an existing Ezsigndocument\&#39;s Ezsignsignatures|
|[**ezsigndocumentGetEzsignsignaturesV2**](#ezsigndocumentgetezsignsignaturesv2) | **GET** /2/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignsignatures | Retrieve an existing Ezsigndocument\&#39;s Ezsignsignatures|
|[**ezsigndocumentGetFormDataV1**](#ezsigndocumentgetformdatav1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getFormData | Retrieve an existing Ezsigndocument\&#39;s Form Data|
|[**ezsigndocumentGetObjectV1**](#ezsigndocumentgetobjectv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID} | Retrieve an existing Ezsigndocument|
|[**ezsigndocumentGetObjectV2**](#ezsigndocumentgetobjectv2) | **GET** /2/object/ezsigndocument/{pkiEzsigndocumentID} | Retrieve an existing Ezsigndocument|
|[**ezsigndocumentGetObjectV3**](#ezsigndocumentgetobjectv3) | **GET** /3/object/ezsigndocument/{pkiEzsigndocumentID} | Retrieve an existing Ezsigndocument|
|[**ezsigndocumentGetTemporaryProofV1**](#ezsigndocumentgettemporaryproofv1) | **GET** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getTemporaryProof | Retrieve the temporary proof|
|[**ezsigndocumentGetWordsPositionsV1**](#ezsigndocumentgetwordspositionsv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/getWordsPositions | Retrieve positions X,Y of given words from a Ezsigndocument|
|[**ezsigndocumentPatchObjectV1**](#ezsigndocumentpatchobjectv1) | **PATCH** /1/object/ezsigndocument/{pkiEzsigndocumentID} | Patch an existing Ezsigndocument|
|[**ezsigndocumentPrefillEzsignformV1**](#ezsigndocumentprefillezsignformv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/prefillEzsignform | Prefill an Ezsignform|
|[**ezsigndocumentSubmitEzsignformV1**](#ezsigndocumentsubmitezsignformv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/submitEzsignform | Submit the Ezsignform|
|[**ezsigndocumentUnsendV1**](#ezsigndocumentunsendv1) | **POST** /1/object/ezsigndocument/{pkiEzsigndocumentID}/unsend | Unsend the Ezsigndocument|

# **ezsigndocumentApplyEzsigntemplateV1**
> EzsigndocumentApplyEzsigntemplateV1Response ezsigndocumentApplyEzsigntemplateV1(ezsigndocumentApplyEzsigntemplateV1Request)

This function is deprecated. Please use *applyEzsigntemplate* instead which is doing the same thing but with a capital \"E\" to normalize the nomenclature.  This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentApplyEzsigntemplateV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentApplyEzsigntemplateV1Request: EzsigndocumentApplyEzsigntemplateV1Request; //

const { status, data } = await apiInstance.ezsigndocumentApplyEzsigntemplateV1(
    pkiEzsigndocumentID,
    ezsigndocumentApplyEzsigntemplateV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentApplyEzsigntemplateV1Request** | **EzsigndocumentApplyEzsigntemplateV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentApplyEzsigntemplateV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentApplyEzsigntemplateV2**
> EzsigndocumentApplyEzsigntemplateV2Response ezsigndocumentApplyEzsigntemplateV2(ezsigndocumentApplyEzsigntemplateV2Request)

This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentApplyEzsigntemplateV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentApplyEzsigntemplateV2Request: EzsigndocumentApplyEzsigntemplateV2Request; //

const { status, data } = await apiInstance.ezsigndocumentApplyEzsigntemplateV2(
    pkiEzsigndocumentID,
    ezsigndocumentApplyEzsigntemplateV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentApplyEzsigntemplateV2Request** | **EzsigndocumentApplyEzsigntemplateV2Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentApplyEzsigntemplateV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentApplyEzsigntemplateglobalV1**
> EzsigndocumentApplyEzsigntemplateglobalV1Response ezsigndocumentApplyEzsigntemplateglobalV1(ezsigndocumentApplyEzsigntemplateglobalV1Request)

This endpoint applies a predefined template to the ezsign document. This allows to automatically apply all the form and signature fields on a document in a single step.  The document must not already have fields otherwise an error will be returned.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentApplyEzsigntemplateglobalV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentApplyEzsigntemplateglobalV1Request: EzsigndocumentApplyEzsigntemplateglobalV1Request; //

const { status, data } = await apiInstance.ezsigndocumentApplyEzsigntemplateglobalV1(
    pkiEzsigndocumentID,
    ezsigndocumentApplyEzsigntemplateglobalV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentApplyEzsigntemplateglobalV1Request** | **EzsigndocumentApplyEzsigntemplateglobalV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentApplyEzsigntemplateglobalV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentCreateEzsignelementsPositionedByWordV1**
> EzsigndocumentCreateEzsignelementsPositionedByWordV1Response ezsigndocumentCreateEzsignelementsPositionedByWordV1(ezsigndocumentCreateEzsignelementsPositionedByWordV1Request)

Using this endpoint, you can create multiple Ezsignsignatures/Ezsignformfieldgroups positioned by word at the same time.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentCreateEzsignelementsPositionedByWordV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentCreateEzsignelementsPositionedByWordV1Request: EzsigndocumentCreateEzsignelementsPositionedByWordV1Request; //

const { status, data } = await apiInstance.ezsigndocumentCreateEzsignelementsPositionedByWordV1(
    pkiEzsigndocumentID,
    ezsigndocumentCreateEzsignelementsPositionedByWordV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentCreateEzsignelementsPositionedByWordV1Request** | **EzsigndocumentCreateEzsignelementsPositionedByWordV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentCreateEzsignelementsPositionedByWordV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentCreateEzsignelementsPositionedByWordV2**
> EzsigndocumentCreateEzsignelementsPositionedByWordV2Response ezsigndocumentCreateEzsignelementsPositionedByWordV2(ezsigndocumentCreateEzsignelementsPositionedByWordV2Request)

Using this endpoint, you can create multiple Ezsignsignatures/Ezsignformfieldgroups positioned by word at the same time.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentCreateEzsignelementsPositionedByWordV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentCreateEzsignelementsPositionedByWordV2Request: EzsigndocumentCreateEzsignelementsPositionedByWordV2Request; //

const { status, data } = await apiInstance.ezsigndocumentCreateEzsignelementsPositionedByWordV2(
    pkiEzsigndocumentID,
    ezsigndocumentCreateEzsignelementsPositionedByWordV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentCreateEzsignelementsPositionedByWordV2Request** | **EzsigndocumentCreateEzsignelementsPositionedByWordV2Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentCreateEzsignelementsPositionedByWordV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentCreateObjectV1**
> EzsigndocumentCreateObjectV1Response ezsigndocumentCreateObjectV1(ezsigndocumentCreateObjectV1Request)

The endpoint allows to create one or many elements at once.  The array can contain simple (Just the object) or compound (The object and its child) objects.  Creating compound elements allows to reduce the multiple requests to create all child objects.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let ezsigndocumentCreateObjectV1Request: Array<EzsigndocumentCreateObjectV1Request>; //

const { status, data } = await apiInstance.ezsigndocumentCreateObjectV1(
    ezsigndocumentCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentCreateObjectV1Request** | **Array<EzsigndocumentCreateObjectV1Request>**|  | |


### Return type

**EzsigndocumentCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**413** | The request was large. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. If the error is recoverable sTemporaryFileUrl will be set and you can use this url to try a new request without sending the file over again |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentCreateObjectV2**
> EzsigndocumentCreateObjectV2Response ezsigndocumentCreateObjectV2(ezsigndocumentCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let ezsigndocumentCreateObjectV2Request: EzsigndocumentCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsigndocumentCreateObjectV2(
    ezsigndocumentCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentCreateObjectV2Request** | **EzsigndocumentCreateObjectV2Request**|  | |


### Return type

**EzsigndocumentCreateObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. If the error is recoverable sTemporaryFileUrl will be set and you can use this url to try a new request without sending the file over again |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentCreateObjectV3**
> EzsigndocumentCreateObjectV3Response ezsigndocumentCreateObjectV3(ezsigndocumentCreateObjectV3Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentCreateObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let ezsigndocumentCreateObjectV3Request: EzsigndocumentCreateObjectV3Request; //

const { status, data } = await apiInstance.ezsigndocumentCreateObjectV3(
    ezsigndocumentCreateObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentCreateObjectV3Request** | **EzsigndocumentCreateObjectV3Request**|  | |


### Return type

**EzsigndocumentCreateObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. If the error is recoverable sTemporaryFileUrl will be set and you can use this url to try a new request without sending the file over again |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentDeclineToSignV1**
> EzsigndocumentDeclineToSignV1Response ezsigndocumentDeclineToSignV1(ezsigndocumentDeclineToSignV1Request)

Decline to sign

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentDeclineToSignV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentDeclineToSignV1Request: EzsigndocumentDeclineToSignV1Request; //

const { status, data } = await apiInstance.ezsigndocumentDeclineToSignV1(
    pkiEzsigndocumentID,
    ezsigndocumentDeclineToSignV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentDeclineToSignV1Request** | **EzsigndocumentDeclineToSignV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentDeclineToSignV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentDeleteObjectV1**
> EzsigndocumentDeleteObjectV1Response ezsigndocumentDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentDeleteObjectV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentEditEzsignannotationsV1**
> EzsigndocumentEditEzsignannotationsV1Response ezsigndocumentEditEzsignannotationsV1(ezsigndocumentEditEzsignannotationsV1Request)

Using this endpoint, you can edit multiple Ezsignannotations at the same time.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentEditEzsignannotationsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentEditEzsignannotationsV1Request: EzsigndocumentEditEzsignannotationsV1Request; //

const { status, data } = await apiInstance.ezsigndocumentEditEzsignannotationsV1(
    pkiEzsigndocumentID,
    ezsigndocumentEditEzsignannotationsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentEditEzsignannotationsV1Request** | **EzsigndocumentEditEzsignannotationsV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentEditEzsignannotationsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentEditEzsignformfieldgroupsV1**
> EzsigndocumentEditEzsignformfieldgroupsV1Response ezsigndocumentEditEzsignformfieldgroupsV1(ezsigndocumentEditEzsignformfieldgroupsV1Request)

Using this endpoint, you can edit multiple Ezsignformfieldgroups at the same time.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentEditEzsignformfieldgroupsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentEditEzsignformfieldgroupsV1Request: EzsigndocumentEditEzsignformfieldgroupsV1Request; //

const { status, data } = await apiInstance.ezsigndocumentEditEzsignformfieldgroupsV1(
    pkiEzsigndocumentID,
    ezsigndocumentEditEzsignformfieldgroupsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentEditEzsignformfieldgroupsV1Request** | **EzsigndocumentEditEzsignformfieldgroupsV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentEditEzsignformfieldgroupsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentEditEzsignsignaturesV1**
> EzsigndocumentEditEzsignsignaturesV1Response ezsigndocumentEditEzsignsignaturesV1(ezsigndocumentEditEzsignsignaturesV1Request)

Using this endpoint, you can edit multiple Ezsignsignatures at the same time.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentEditEzsignsignaturesV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentEditEzsignsignaturesV1Request: EzsigndocumentEditEzsignsignaturesV1Request; //

const { status, data } = await apiInstance.ezsigndocumentEditEzsignsignaturesV1(
    pkiEzsigndocumentID,
    ezsigndocumentEditEzsignsignaturesV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentEditEzsignsignaturesV1Request** | **EzsigndocumentEditEzsignsignaturesV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentEditEzsignsignaturesV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentEditEzsignsignaturesV2**
> EzsigndocumentEditEzsignsignaturesV2Response ezsigndocumentEditEzsignsignaturesV2(ezsigndocumentEditEzsignsignaturesV2Request)

Using this endpoint, you can edit multiple Ezsignsignatures at the same time.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentEditEzsignsignaturesV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentEditEzsignsignaturesV2Request: EzsigndocumentEditEzsignsignaturesV2Request; //

const { status, data } = await apiInstance.ezsigndocumentEditEzsignsignaturesV2(
    pkiEzsigndocumentID,
    ezsigndocumentEditEzsignsignaturesV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentEditEzsignsignaturesV2Request** | **EzsigndocumentEditEzsignsignaturesV2Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentEditEzsignsignaturesV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentEditObjectV1**
> EzsigndocumentEditObjectV1Response ezsigndocumentEditObjectV1(ezsigndocumentEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentEditObjectV1Request: EzsigndocumentEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigndocumentEditObjectV1(
    pkiEzsigndocumentID,
    ezsigndocumentEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentEditObjectV1Request** | **EzsigndocumentEditObjectV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. If the error is recoverable sTemporaryFileUrl will be set and you can use this url to try a new request without sending the file over again |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentEndPrematurelyV1**
> EzsigndocumentEndPrematurelyV1Response ezsigndocumentEndPrematurelyV1(body)

End prematurely an Ezsigndocument when some signatures are still required

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsigndocumentEndPrematurelyV1(
    pkiEzsigndocumentID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentEndPrematurelyV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentExtractTextV1**
> EzsigndocumentExtractTextV1Response ezsigndocumentExtractTextV1(ezsigndocumentExtractTextV1Request)

Extract text from Ezsigndocument area

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentExtractTextV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentExtractTextV1Request: EzsigndocumentExtractTextV1Request; //

const { status, data } = await apiInstance.ezsigndocumentExtractTextV1(
    pkiEzsigndocumentID,
    ezsigndocumentExtractTextV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentExtractTextV1Request** | **EzsigndocumentExtractTextV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentExtractTextV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentFlattenV1**
> EzsigndocumentFlattenV1Response ezsigndocumentFlattenV1(body)

Flatten an Ezsigndocument signatures, forms and annotations. This process finalizes the PDF so that the forms and annotations become part of the document content and cannot be edited.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsigndocumentFlattenV1(
    pkiEzsigndocumentID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentFlattenV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetActionableElementsV1**
> EzsigndocumentGetActionableElementsV1Response ezsigndocumentGetActionableElementsV1()

Return the Ezsignsignatures that can be signed and Ezsignformfieldgroups that can be filled by the current user at the current step in the process.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3. 

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetActionableElementsV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetActionableElementsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetActionableElementsV2**
> EzsigndocumentGetActionableElementsV2Response ezsigndocumentGetActionableElementsV2()

Return the Ezsignsignatures that can be signed and Ezsignformfieldgroups that can be filled by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetActionableElementsV2(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetActionableElementsV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetAttachmentsV1**
> EzsigndocumentGetAttachmentsV1Response ezsigndocumentGetAttachmentsV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetAttachmentsV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetAttachmentsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetCompletedElementsV1**
> EzsigndocumentGetCompletedElementsV1Response ezsigndocumentGetCompletedElementsV1()

Return the completed Ezsignsignatures, Ezsignformfieldgroups and Ezsignannotations at the current step in the process  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetCompletedElementsV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetCompletedElementsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetCompletedElementsV2**
> EzsigndocumentGetCompletedElementsV2Response ezsigndocumentGetCompletedElementsV2()

Return the completed Ezsignsignatures, Ezsignformfieldgroups and Ezsignannotations at the current step in the process

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetCompletedElementsV2(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetCompletedElementsV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetDownloadUrlV1**
> EzsigndocumentGetDownloadUrlV1Response ezsigndocumentGetDownloadUrlV1()

This endpoint returns URLs to different files that can be downloaded during the signing process.  These links will expire after 5 minutes so the download of the file should be made soon after retrieving the link.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let eDocumentType: 'Original' | 'Initial' | 'SignatureReady' | 'Signed' | 'Proof' | 'Proofdocument'; //The type of document to retrieve.  1. **original** Is the original document before any repair or conversion were applied. **Initial** Is the initial document after initial signature were applied. 2. **SignatureReady** Is the version containing the annotations/form to show the signer. 3. **Signed** Is the final document once all signatures were applied in current document if eEzsignfolderCompletion is PerEzsigndocument.<br>     Is the final document once all signatures were applied in all documents if eEzsignfolderCompletion is PerEzsignfolder. 4. **Proofdocument** Is the evidence report. 5. **Proof** Is the complete evidence archive including all of the above and more.  (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetDownloadUrlV1(
    pkiEzsigndocumentID,
    eDocumentType
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|
| **eDocumentType** | [**&#39;Original&#39; | &#39;Initial&#39; | &#39;SignatureReady&#39; | &#39;Signed&#39; | &#39;Proof&#39; | &#39;Proofdocument&#39;**]**Array<&#39;Original&#39; &#124; &#39;Initial&#39; &#124; &#39;SignatureReady&#39; &#124; &#39;Signed&#39; &#124; &#39;Proof&#39; &#124; &#39;Proofdocument&#39;>** | The type of document to retrieve.  1. **original** Is the original document before any repair or conversion were applied. **Initial** Is the initial document after initial signature were applied. 2. **SignatureReady** Is the version containing the annotations/form to show the signer. 3. **Signed** Is the final document once all signatures were applied in current document if eEzsignfolderCompletion is PerEzsigndocument.&lt;br&gt;     Is the final document once all signatures were applied in all documents if eEzsignfolderCompletion is PerEzsignfolder. 4. **Proofdocument** Is the evidence report. 5. **Proof** Is the complete evidence archive including all of the above and more.  | defaults to undefined|


### Return type

**EzsigndocumentGetDownloadUrlV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsignannotationsV1**
> EzsigndocumentGetEzsignannotationsV1Response ezsigndocumentGetEzsignannotationsV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsignannotationsV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsignannotationsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsigndiscussionsV1**
> EzsigndocumentGetEzsigndiscussionsV1Response ezsigndocumentGetEzsigndiscussionsV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsigndiscussionsV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsigndiscussionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsignformfieldgroupsV1**
> EzsigndocumentGetEzsignformfieldgroupsV1Response ezsigndocumentGetEzsignformfieldgroupsV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsignformfieldgroupsV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsignformfieldgroupsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsignpagesV1**
> EzsigndocumentGetEzsignpagesV1Response ezsigndocumentGetEzsignpagesV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsignpagesV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsignpagesV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsignsignaturesAutomaticV1**
> EzsigndocumentGetEzsignsignaturesAutomaticV1Response ezsigndocumentGetEzsignsignaturesAutomaticV1()

Return the Ezsignsignatures that can be signed by the current user at the current step in the process

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsignsignaturesAutomaticV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsignsignaturesAutomaticV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsignsignaturesV1**
> EzsigndocumentGetEzsignsignaturesV1Response ezsigndocumentGetEzsignsignaturesV1()

Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsignsignaturesV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsignsignaturesV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetEzsignsignaturesV2**
> EzsigndocumentGetEzsignsignaturesV2Response ezsigndocumentGetEzsignsignaturesV2()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetEzsignsignaturesV2(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetEzsignsignaturesV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetFormDataV1**
> EzsigndocumentGetFormDataV1Response ezsigndocumentGetFormDataV1()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetFormDataV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetFormDataV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/zip, text/csv


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetObjectV1**
> EzsigndocumentGetObjectV1Response ezsigndocumentGetObjectV1()

Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetObjectV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetObjectV2**
> EzsigndocumentGetObjectV2Response ezsigndocumentGetObjectV2()

Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetObjectV2(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetObjectV3**
> EzsigndocumentGetObjectV3Response ezsigndocumentGetObjectV3()



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetObjectV3(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetObjectV3Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetTemporaryProofV1**
> EzsigndocumentGetTemporaryProofV1Response ezsigndocumentGetTemporaryProofV1()

Retrieve the temporary proof while the Ezsigndocument is being processed since the proof isn\'t available until the Ezsigndocument is completed

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigndocumentGetTemporaryProofV1(
    pkiEzsigndocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetTemporaryProofV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentGetWordsPositionsV1**
> EzsigndocumentGetWordsPositionsV1Response ezsigndocumentGetWordsPositionsV1(ezsigndocumentGetWordsPositionsV1Request)



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentGetWordsPositionsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentGetWordsPositionsV1Request: EzsigndocumentGetWordsPositionsV1Request; //

const { status, data } = await apiInstance.ezsigndocumentGetWordsPositionsV1(
    pkiEzsigndocumentID,
    ezsigndocumentGetWordsPositionsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentGetWordsPositionsV1Request** | **EzsigndocumentGetWordsPositionsV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentGetWordsPositionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentPatchObjectV1**
> EzsigndocumentPatchObjectV1Response ezsigndocumentPatchObjectV1(ezsigndocumentPatchObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentPatchObjectV1Request: EzsigndocumentPatchObjectV1Request; //

const { status, data } = await apiInstance.ezsigndocumentPatchObjectV1(
    pkiEzsigndocumentID,
    ezsigndocumentPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentPatchObjectV1Request** | **EzsigndocumentPatchObjectV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentPatchObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentPrefillEzsignformV1**
> EzsigndocumentPrefillEzsignformV1Response ezsigndocumentPrefillEzsignformV1(ezsigndocumentPrefillEzsignformV1Request)

Using this endpoint, you can prefill an Ezsignform.  To fill Ezsignformfield with type **Dropdown**, **Text**, **Textarea**, **Checkbox**, **Date**, **Number**, you must provide properties sEzsignformfieldgroupLabel and sEzsignformfieldLabel.  To fill Ezsignformfield with type **Radio**, you must provide only the property sEzsignformfieldgroupLabel.  In **PowerAutomate** if you need to add a line feed in sEzsignformfieldEnteredvalue, you should do it like this: concat(\'string1\',decodeUriComponent(\'%0A\'),\'string2\',decodeUriComponent(\'%0A\'),\'string3\')

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentPrefillEzsignformV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentPrefillEzsignformV1Request: EzsigndocumentPrefillEzsignformV1Request; //

const { status, data } = await apiInstance.ezsigndocumentPrefillEzsignformV1(
    pkiEzsigndocumentID,
    ezsigndocumentPrefillEzsignformV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentPrefillEzsignformV1Request** | **EzsigndocumentPrefillEzsignformV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentPrefillEzsignformV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentSubmitEzsignformV1**
> EzsigndocumentSubmitEzsignformV1Response ezsigndocumentSubmitEzsignformV1(ezsigndocumentSubmitEzsignformV1Request)



### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration,
    EzsigndocumentSubmitEzsignformV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let ezsigndocumentSubmitEzsignformV1Request: EzsigndocumentSubmitEzsignformV1Request; //

const { status, data } = await apiInstance.ezsigndocumentSubmitEzsignformV1(
    pkiEzsigndocumentID,
    ezsigndocumentSubmitEzsignformV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigndocumentSubmitEzsignformV1Request** | **EzsigndocumentSubmitEzsignformV1Request**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentSubmitEzsignformV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigndocumentUnsendV1**
> EzsigndocumentUnsendV1Response ezsigndocumentUnsendV1(body)

Once an Ezsigndocument has been sent to signatories, it cannot be modified.  Using this endpoint, you can unsend the Ezsigndocument and make it modifiable again.  Signatories will receive an email informing them the signature process was aborted and they might receive a new invitation to sign.  ⚠️ Warning: Any signature previously made by signatories on this Ezsigndocumentswill be lost.

### Example

```typescript
import {
    ObjectEzsigndocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigndocumentApi(configuration);

let pkiEzsigndocumentID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsigndocumentUnsendV1(
    pkiEzsigndocumentID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsigndocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigndocumentUnsendV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

