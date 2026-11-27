# ObjectEzsigntemplatepublicApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatepublicCreateEzsignfolderV1**](#ezsigntemplatepubliccreateezsignfolderv1) | **POST** /1/object/ezsigntemplatepublic/createEzsignfolder | Create an Ezsignfolder|
|[**ezsigntemplatepublicCreateObjectV1**](#ezsigntemplatepubliccreateobjectv1) | **POST** /1/object/ezsigntemplatepublic | Create a new Ezsigntemplatepublic|
|[**ezsigntemplatepublicDeleteObjectV1**](#ezsigntemplatepublicdeleteobjectv1) | **DELETE** /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID} | Delete an existing Ezsigntemplatepublic|
|[**ezsigntemplatepublicEditObjectV1**](#ezsigntemplatepubliceditobjectv1) | **PUT** /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID} | Edit an existing Ezsigntemplatepublic|
|[**ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1**](#ezsigntemplatepublicgetezsigntemplatepublicdetailsv1) | **POST** /1/object/ezsigntemplatepublic/getEzsigntemplatepublicDetails | Retrieve the Ezsigntemplatepublic details|
|[**ezsigntemplatepublicGetFormsDataV1**](#ezsigntemplatepublicgetformsdatav1) | **GET** /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}/getFormsData | Retrieve an existing Ezsigntemplatepublic\&#39;s forms data|
|[**ezsigntemplatepublicGetListV1**](#ezsigntemplatepublicgetlistv1) | **GET** /1/object/ezsigntemplatepublic/getList | Retrieve Ezsigntemplatepublic list|
|[**ezsigntemplatepublicGetObjectV2**](#ezsigntemplatepublicgetobjectv2) | **GET** /2/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID} | Retrieve an existing Ezsigntemplatepublic|
|[**ezsigntemplatepublicResetLimitExceededCounterV1**](#ezsigntemplatepublicresetlimitexceededcounterv1) | **POST** /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}/resetLimitExceededCounter | Reset the limit exceeded counter|
|[**ezsigntemplatepublicResetUrlV1**](#ezsigntemplatepublicreseturlv1) | **POST** /1/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}/resetUrl | Reset the Ezsigntemplatepublic url|

# **ezsigntemplatepublicCreateEzsignfolderV1**
> EzsigntemplatepublicCreateEzsignfolderV1Response ezsigntemplatepublicCreateEzsignfolderV1(ezsigntemplatepublicCreateEzsignfolderV1Request)

Create an Ezsignfolder

### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration,
    EzsigntemplatepublicCreateEzsignfolderV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let ezsigntemplatepublicCreateEzsignfolderV1Request: EzsigntemplatepublicCreateEzsignfolderV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepublicCreateEzsignfolderV1(
    ezsigntemplatepublicCreateEzsignfolderV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepublicCreateEzsignfolderV1Request** | **EzsigntemplatepublicCreateEzsignfolderV1Request**|  | |


### Return type

**EzsigntemplatepublicCreateEzsignfolderV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicCreateObjectV1**
> EzsigntemplatepublicCreateObjectV1Response ezsigntemplatepublicCreateObjectV1(ezsigntemplatepublicCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration,
    EzsigntemplatepublicCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let ezsigntemplatepublicCreateObjectV1Request: EzsigntemplatepublicCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepublicCreateObjectV1(
    ezsigntemplatepublicCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepublicCreateObjectV1Request** | **EzsigntemplatepublicCreateObjectV1Request**|  | |


### Return type

**EzsigntemplatepublicCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicDeleteObjectV1**
> EzsigntemplatepublicDeleteObjectV1Response ezsigntemplatepublicDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let pkiEzsigntemplatepublicID: number; //The unique ID of the Ezsigntemplatepublic (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepublicDeleteObjectV1(
    pkiEzsigntemplatepublicID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepublicID** | [**number**] | The unique ID of the Ezsigntemplatepublic | defaults to undefined|


### Return type

**EzsigntemplatepublicDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicEditObjectV1**
> EzsigntemplatepublicEditObjectV1Response ezsigntemplatepublicEditObjectV1(ezsigntemplatepublicEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration,
    EzsigntemplatepublicEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let pkiEzsigntemplatepublicID: number; //The unique ID of the Ezsigntemplatepublic (default to undefined)
let ezsigntemplatepublicEditObjectV1Request: EzsigntemplatepublicEditObjectV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepublicEditObjectV1(
    pkiEzsigntemplatepublicID,
    ezsigntemplatepublicEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepublicEditObjectV1Request** | **EzsigntemplatepublicEditObjectV1Request**|  | |
| **pkiEzsigntemplatepublicID** | [**number**] | The unique ID of the Ezsigntemplatepublic | defaults to undefined|


### Return type

**EzsigntemplatepublicEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1**
> EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1(ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request)

Retrieve the Ezsigntemplatepublic details

### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration,
    EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request: EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request; //

const { status, data } = await apiInstance.ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1(
    ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request** | **EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Request**|  | |


### Return type

**EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | OK |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicGetFormsDataV1**
> EzsigntemplatepublicGetFormsDataV1Response ezsigntemplatepublicGetFormsDataV1()



### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let pkiEzsigntemplatepublicID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepublicGetFormsDataV1(
    pkiEzsigntemplatepublicID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepublicID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepublicGetFormsDataV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/zip


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicGetListV1**
> EzsigntemplatepublicGetListV1Response ezsigntemplatepublicGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eEzsigntemplatepublicLimittype | Hour<br>Day<br>Month<br>Total |

### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let eOrderBy: 'pkiEzsigntemplatepublicID_ASC' | 'pkiEzsigntemplatepublicID_DESC' | 'fkiEzsignfoldertypeID_ASC' | 'fkiEzsignfoldertypeID_DESC' | 'sEzsignfoldertypeNameX_ASC' | 'sEzsignfoldertypeNameX_DESC' | 'fkiUserlogintypeID_ASC' | 'fkiUserlogintypeID_DESC' | 'fkiEzsigntemplateID_ASC' | 'fkiEzsigntemplateID_DESC' | 'fkiEzsigntemplatepackageID_ASC' | 'fkiEzsigntemplatepackageID_DESC' | 'sEzsigntemplatepublicDescription_ASC' | 'sEzsigntemplatepublicDescription_DESC' | 'bEzsigntemplatepublicIsactive_ASC' | 'bEzsigntemplatepublicIsactive_DESC' | 'tEzsigntemplatepublicNote_ASC' | 'tEzsigntemplatepublicNote_DESC' | 'eEzsigntemplatepublicLimittype_ASC' | 'eEzsigntemplatepublicLimittype_DESC' | 'iEzsigntemplatepublicLimit_ASC' | 'iEzsigntemplatepublicLimit_DESC' | 'iEzsigntemplatepublicLimitexceeded_ASC' | 'iEzsigntemplatepublicLimitexceeded_DESC' | 'dtEzsigntemplatepublicLimitexceededsince_ASC' | 'dtEzsigntemplatepublicLimitexceededsince_DESC' | 'iEzsignfolder_ASC' | 'iEzsignfolder_DESC' | 'iEzsigndocument_ASC' | 'iEzsigndocument_DESC' | 'sEzsigntemplatepublicEzsigntemplatedescription_ASC' | 'sEzsigntemplatepublicEzsigntemplatedescription_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepublicGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiEzsigntemplatepublicID_ASC&#39; | &#39;pkiEzsigntemplatepublicID_DESC&#39; | &#39;fkiEzsignfoldertypeID_ASC&#39; | &#39;fkiEzsignfoldertypeID_DESC&#39; | &#39;sEzsignfoldertypeNameX_ASC&#39; | &#39;sEzsignfoldertypeNameX_DESC&#39; | &#39;fkiUserlogintypeID_ASC&#39; | &#39;fkiUserlogintypeID_DESC&#39; | &#39;fkiEzsigntemplateID_ASC&#39; | &#39;fkiEzsigntemplateID_DESC&#39; | &#39;fkiEzsigntemplatepackageID_ASC&#39; | &#39;fkiEzsigntemplatepackageID_DESC&#39; | &#39;sEzsigntemplatepublicDescription_ASC&#39; | &#39;sEzsigntemplatepublicDescription_DESC&#39; | &#39;bEzsigntemplatepublicIsactive_ASC&#39; | &#39;bEzsigntemplatepublicIsactive_DESC&#39; | &#39;tEzsigntemplatepublicNote_ASC&#39; | &#39;tEzsigntemplatepublicNote_DESC&#39; | &#39;eEzsigntemplatepublicLimittype_ASC&#39; | &#39;eEzsigntemplatepublicLimittype_DESC&#39; | &#39;iEzsigntemplatepublicLimit_ASC&#39; | &#39;iEzsigntemplatepublicLimit_DESC&#39; | &#39;iEzsigntemplatepublicLimitexceeded_ASC&#39; | &#39;iEzsigntemplatepublicLimitexceeded_DESC&#39; | &#39;dtEzsigntemplatepublicLimitexceededsince_ASC&#39; | &#39;dtEzsigntemplatepublicLimitexceededsince_DESC&#39; | &#39;iEzsignfolder_ASC&#39; | &#39;iEzsignfolder_DESC&#39; | &#39;iEzsigndocument_ASC&#39; | &#39;iEzsigndocument_DESC&#39; | &#39;sEzsigntemplatepublicEzsigntemplatedescription_ASC&#39; | &#39;sEzsigntemplatepublicEzsigntemplatedescription_DESC&#39;**]**Array<&#39;pkiEzsigntemplatepublicID_ASC&#39; &#124; &#39;pkiEzsigntemplatepublicID_DESC&#39; &#124; &#39;fkiEzsignfoldertypeID_ASC&#39; &#124; &#39;fkiEzsignfoldertypeID_DESC&#39; &#124; &#39;sEzsignfoldertypeNameX_ASC&#39; &#124; &#39;sEzsignfoldertypeNameX_DESC&#39; &#124; &#39;fkiUserlogintypeID_ASC&#39; &#124; &#39;fkiUserlogintypeID_DESC&#39; &#124; &#39;fkiEzsigntemplateID_ASC&#39; &#124; &#39;fkiEzsigntemplateID_DESC&#39; &#124; &#39;fkiEzsigntemplatepackageID_ASC&#39; &#124; &#39;fkiEzsigntemplatepackageID_DESC&#39; &#124; &#39;sEzsigntemplatepublicDescription_ASC&#39; &#124; &#39;sEzsigntemplatepublicDescription_DESC&#39; &#124; &#39;bEzsigntemplatepublicIsactive_ASC&#39; &#124; &#39;bEzsigntemplatepublicIsactive_DESC&#39; &#124; &#39;tEzsigntemplatepublicNote_ASC&#39; &#124; &#39;tEzsigntemplatepublicNote_DESC&#39; &#124; &#39;eEzsigntemplatepublicLimittype_ASC&#39; &#124; &#39;eEzsigntemplatepublicLimittype_DESC&#39; &#124; &#39;iEzsigntemplatepublicLimit_ASC&#39; &#124; &#39;iEzsigntemplatepublicLimit_DESC&#39; &#124; &#39;iEzsigntemplatepublicLimitexceeded_ASC&#39; &#124; &#39;iEzsigntemplatepublicLimitexceeded_DESC&#39; &#124; &#39;dtEzsigntemplatepublicLimitexceededsince_ASC&#39; &#124; &#39;dtEzsigntemplatepublicLimitexceededsince_DESC&#39; &#124; &#39;iEzsignfolder_ASC&#39; &#124; &#39;iEzsignfolder_DESC&#39; &#124; &#39;iEzsigndocument_ASC&#39; &#124; &#39;iEzsigndocument_DESC&#39; &#124; &#39;sEzsigntemplatepublicEzsigntemplatedescription_ASC&#39; &#124; &#39;sEzsigntemplatepublicEzsigntemplatedescription_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsigntemplatepublicGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicGetObjectV2**
> EzsigntemplatepublicGetObjectV2Response ezsigntemplatepublicGetObjectV2()



### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let pkiEzsigntemplatepublicID: number; //The unique ID of the Ezsigntemplatepublic (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatepublicGetObjectV2(
    pkiEzsigntemplatepublicID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatepublicID** | [**number**] | The unique ID of the Ezsigntemplatepublic | defaults to undefined|


### Return type

**EzsigntemplatepublicGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicResetLimitExceededCounterV1**
> EzsigntemplatepublicResetLimitExceededCounterV1Response ezsigntemplatepublicResetLimitExceededCounterV1(body)



### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let pkiEzsigntemplatepublicID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsigntemplatepublicResetLimitExceededCounterV1(
    pkiEzsigntemplatepublicID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsigntemplatepublicID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepublicResetLimitExceededCounterV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsigntemplatepublicResetUrlV1**
> EzsigntemplatepublicResetUrlV1Response ezsigntemplatepublicResetUrlV1(body)



### Example

```typescript
import {
    ObjectEzsigntemplatepublicApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatepublicApi(configuration);

let pkiEzsigntemplatepublicID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.ezsigntemplatepublicResetUrlV1(
    pkiEzsigntemplatepublicID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiEzsigntemplatepublicID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatepublicResetUrlV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

