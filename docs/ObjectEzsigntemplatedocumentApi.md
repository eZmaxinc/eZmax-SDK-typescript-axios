# ObjectEzsigntemplatedocumentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatedocumentCreateObjectV1**](#ezsigntemplatedocumentcreateobjectv1) | **POST** /1/object/ezsigntemplatedocument | Create a new Ezsigntemplatedocument|
|[**ezsigntemplatedocumentDownloadV1**](#ezsigntemplatedocumentdownloadv1) | **GET** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/download | Retrieve an existing Ezsigntemplatedocument\&#39;s original file|
|[**ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1**](#ezsigntemplatedocumenteditezsigntemplatedocumentpagerecognitionsv1) | **PUT** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatedocumentpagerecognitions | Edit multiple Ezsigntemplatedocumentpagerecognitions|
|[**ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1**](#ezsigntemplatedocumenteditezsigntemplateformfieldgroupsv1) | **PUT** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplateformfieldgroups | Edit multiple Ezsigntemplateformfieldgroups|
|[**ezsigntemplatedocumentEditEzsigntemplatesignaturesV1**](#ezsigntemplatedocumenteditezsigntemplatesignaturesv1) | **PUT** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatesignatures | Edit multiple Ezsigntemplatesignatures|
|[**ezsigntemplatedocumentEditEzsigntemplatesignaturesV2**](#ezsigntemplatedocumenteditezsigntemplatesignaturesv2) | **PUT** /2/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatesignatures | Edit multiple Ezsigntemplatesignatures|
|[**ezsigntemplatedocumentEditObjectV1**](#ezsigntemplatedocumenteditobjectv1) | **PUT** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID} | Edit an existing Ezsigntemplatedocument|
|[**ezsigntemplatedocumentExtractTextV1**](#ezsigntemplatedocumentextracttextv1) | **POST** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/extractText | Extract text from Ezsigntemplatedocument area|
|[**ezsigntemplatedocumentFlattenV1**](#ezsigntemplatedocumentflattenv1) | **POST** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/flatten | Flatten|
|[**ezsigntemplatedocumentGetEzsigntemplatedocumentpagerecognitionsV1**](#ezsigntemplatedocumentgetezsigntemplatedocumentpagerecognitionsv1) | **GET** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplatedocumentpagerecognitions | Retrieve an existing Ezsigntemplatedocument\&#39;s Ezsigntemplatedocumentpagerecognitions|
|[**ezsigntemplatedocumentGetEzsigntemplatedocumentpagesV1**](#ezsigntemplatedocumentgetezsigntemplatedocumentpagesv1) | **GET** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplatedocumentpages | Retrieve an existing Ezsigntemplatedocument\&#39;s Ezsigntemplatedocumentpages|
|[**ezsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1**](#ezsigntemplatedocumentgetezsigntemplateformfieldgroupsv1) | **GET** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplateformfieldgroups | Retrieve an existing Ezsigntemplatedocument\&#39;s Ezsigntemplateformfieldgroups|
|[**ezsigntemplatedocumentGetEzsigntemplatesignaturesV2**](#ezsigntemplatedocumentgetezsigntemplatesignaturesv2) | **GET** /2/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplatesignatures | Retrieve an existing Ezsigntemplatedocument\&#39;s Ezsigntemplatesignatures|
|[**ezsigntemplatedocumentGetObjectV2**](#ezsigntemplatedocumentgetobjectv2) | **GET** /2/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID} | Retrieve an existing Ezsigntemplatedocument|
|[**ezsigntemplatedocumentGetWordsPositionsV1**](#ezsigntemplatedocumentgetwordspositionsv1) | **POST** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getWordsPositions | Retrieve positions X,Y of given words from a Ezsigntemplatedocument|
|[**ezsigntemplatedocumentPatchObjectV1**](#ezsigntemplatedocumentpatchobjectv1) | **PATCH** /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID} | Patch an existing Ezsigntemplatedocument|

# **ezsigntemplatedocumentCreateObjectV1**
> EzsigntemplatedocumentCreateObjectV1Response ezsigntemplatedocumentCreateObjectV1(ezsigntemplatedocumentCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let ezsigntemplatedocumentCreateObjectV1Request: EzsigntemplatedocumentCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentCreateObjectV1(
    ezsigntemplatedocumentCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentCreateObjectV1Request** | **EzsigntemplatedocumentCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatedocumentCreateObjectV1Response**

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

# **ezsigntemplatedocumentDownloadV1**
> ezsigntemplatedocumentDownloadV1()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentDownloadV1(
    pkiEzsigntemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

void (empty response body)

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**302** | The user has been redirected |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1**
> EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1(ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request)

Edit multiple Ezsigntemplatedocumentpagerecognitions

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request: EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request** | **EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Response**

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

# **ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1**
> EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1(ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request)

Using this endpoint, you can edit multiple Ezsigntemplateformfieldgroups at the same time.

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request: EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request** | **EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentEditEzsigntemplateformfieldgroupsV1Response**

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

# **ezsigntemplatedocumentEditEzsigntemplatesignaturesV1**
> EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response ezsigntemplatedocumentEditEzsigntemplatesignaturesV1(ezsigntemplatedocumentEditEzsigntemplatesignaturesV1Request)

Using this endpoint, you can edit multiple Ezsigntemplatesignatures at the same time.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentEditEzsigntemplatesignaturesV1Request: EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentEditEzsigntemplatesignaturesV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentEditEzsigntemplatesignaturesV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentEditEzsigntemplatesignaturesV1Request** | **EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentEditEzsigntemplatesignaturesV1Response**

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

# **ezsigntemplatedocumentEditEzsigntemplatesignaturesV2**
> EzsigntemplatedocumentEditEzsigntemplatesignaturesV2Response ezsigntemplatedocumentEditEzsigntemplatesignaturesV2(ezsigntemplatedocumentEditEzsigntemplatesignaturesV2Request)

Using this endpoint, you can edit multiple Ezsigntemplatesignatures at the same time.

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentEditEzsigntemplatesignaturesV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentEditEzsigntemplatesignaturesV2Request: EzsigntemplatedocumentEditEzsigntemplatesignaturesV2Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentEditEzsigntemplatesignaturesV2(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentEditEzsigntemplatesignaturesV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentEditEzsigntemplatesignaturesV2Request** | **EzsigntemplatedocumentEditEzsigntemplatesignaturesV2Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentEditEzsigntemplatesignaturesV2Response**

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

# **ezsigntemplatedocumentEditObjectV1**
> EzsigntemplatedocumentEditObjectV1Response ezsigntemplatedocumentEditObjectV1(ezsigntemplatedocumentEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentEditObjectV1Request: EzsigntemplatedocumentEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentEditObjectV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentEditObjectV1Request** | **EzsigntemplatedocumentEditObjectV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentEditObjectV1Response**

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

# **ezsigntemplatedocumentExtractTextV1**
> EzsigntemplatedocumentExtractTextV1Response ezsigntemplatedocumentExtractTextV1(ezsigntemplatedocumentExtractTextV1Request)

Extract text from Ezsigntemplatedocument area

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentExtractTextV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentExtractTextV1Request: EzsigntemplatedocumentExtractTextV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentExtractTextV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentExtractTextV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentExtractTextV1Request** | **EzsigntemplatedocumentExtractTextV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentExtractTextV1Response**

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

# **ezsigntemplatedocumentFlattenV1**
> EzsigntemplatedocumentFlattenV1Response ezsigntemplatedocumentFlattenV1(body)

Flatten an Ezsigntemplatedocument signatures, forms and annotations. This process finalizes the PDF so that the forms and annotations become part of the document content and cannot be edited.

### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsigntemplatedocumentFlattenV1(
    pkiEzsigntemplatedocumentID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentFlattenV1Response**

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

# **ezsigntemplatedocumentGetEzsigntemplatedocumentpagerecognitionsV1**
> EzsigntemplatedocumentGetEzsigntemplatedocumentpagerecognitionsV1Response ezsigntemplatedocumentGetEzsigntemplatedocumentpagerecognitionsV1()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentGetEzsigntemplatedocumentpagerecognitionsV1(
    pkiEzsigntemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentGetEzsigntemplatedocumentpagerecognitionsV1Response**

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

# **ezsigntemplatedocumentGetEzsigntemplatedocumentpagesV1**
> EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response ezsigntemplatedocumentGetEzsigntemplatedocumentpagesV1()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentGetEzsigntemplatedocumentpagesV1(
    pkiEzsigntemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response**

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

# **ezsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1**
> EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response ezsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1(
    pkiEzsigntemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1Response**

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

# **ezsigntemplatedocumentGetEzsigntemplatesignaturesV2**
> EzsigntemplatedocumentGetEzsigntemplatesignaturesV2Response ezsigntemplatedocumentGetEzsigntemplatesignaturesV2()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentGetEzsigntemplatesignaturesV2(
    pkiEzsigntemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentGetEzsigntemplatesignaturesV2Response**

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

# **ezsigntemplatedocumentGetObjectV2**
> EzsigntemplatedocumentGetObjectV2Response ezsigntemplatedocumentGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatedocumentGetObjectV2(
    pkiEzsigntemplatedocumentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentGetObjectV2Response**

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

# **ezsigntemplatedocumentGetWordsPositionsV1**
> EzsigntemplatedocumentGetWordsPositionsV1Response ezsigntemplatedocumentGetWordsPositionsV1(ezsigntemplatedocumentGetWordsPositionsV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentGetWordsPositionsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentGetWordsPositionsV1Request: EzsigntemplatedocumentGetWordsPositionsV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentGetWordsPositionsV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentGetWordsPositionsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentGetWordsPositionsV1Request** | **EzsigntemplatedocumentGetWordsPositionsV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentGetWordsPositionsV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatedocumentPatchObjectV1**
> EzsigntemplatedocumentPatchObjectV1Response ezsigntemplatedocumentPatchObjectV1(ezsigntemplatedocumentPatchObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatedocumentApi,
    Configuration,
    EzsigntemplatedocumentPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatedocumentApi(configuration);

let pkiEzsigntemplatedocumentID: number; // (default to undefined)
let ezsigntemplatedocumentPatchObjectV1Request: EzsigntemplatedocumentPatchObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatedocumentPatchObjectV1(
    pkiEzsigntemplatedocumentID,
    ezsigntemplatedocumentPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatedocumentPatchObjectV1Request** | **EzsigntemplatedocumentPatchObjectV1Request**|  | |
| **pkiEzsigntemplatedocumentID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatedocumentPatchObjectV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

