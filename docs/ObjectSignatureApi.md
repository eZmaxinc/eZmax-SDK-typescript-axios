# ObjectSignatureApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**signatureCreateObjectV1**](#signaturecreateobjectv1) | **POST** /1/object/signature | Create a new Signature|
|[**signatureDeleteObjectV1**](#signaturedeleteobjectv1) | **DELETE** /1/object/signature/{pkiSignatureID} | Delete an existing Signature|
|[**signatureEditObjectV1**](#signatureeditobjectv1) | **PUT** /1/object/signature/{pkiSignatureID} | Edit an existing Signature|
|[**signatureGetObjectV2**](#signaturegetobjectv2) | **GET** /2/object/signature/{pkiSignatureID} | Retrieve an existing Signature|
|[**signatureGetObjectV3**](#signaturegetobjectv3) | **GET** /3/object/signature/{pkiSignatureID} | Retrieve an existing Signature|
|[**signatureGetSVGInitialsV1**](#signaturegetsvginitialsv1) | **GET** /1/object/signature/{pkiSignatureID}/getSVGInitials | Retrieve an existing Signature initial SVG|
|[**signatureGetSVGSignatureV1**](#signaturegetsvgsignaturev1) | **GET** /1/object/signature/{pkiSignatureID}/getSVGSignature | Retrieve an existing Signature SVG|

# **signatureCreateObjectV1**
> SignatureCreateObjectV1Response signatureCreateObjectV1(signatureCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration,
    SignatureCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let signatureCreateObjectV1Request: SignatureCreateObjectV1Request; //

const { status, data } = await apiInstance.signatureCreateObjectV1(
    signatureCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **signatureCreateObjectV1Request** | **SignatureCreateObjectV1Request**|  | |


### Return type

**SignatureCreateObjectV1Response**

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

# **signatureDeleteObjectV1**
> SignatureDeleteObjectV1Response signatureDeleteObjectV1()



### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let pkiSignatureID: number; //The unique ID of the Signature (default to undefined)

const { status, data } = await apiInstance.signatureDeleteObjectV1(
    pkiSignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSignatureID** | [**number**] | The unique ID of the Signature | defaults to undefined|


### Return type

**SignatureDeleteObjectV1Response**

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

# **signatureEditObjectV1**
> SignatureEditObjectV1Response signatureEditObjectV1(signatureEditObjectV1Request)



### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration,
    SignatureEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let pkiSignatureID: number; //The unique ID of the Signature (default to undefined)
let signatureEditObjectV1Request: SignatureEditObjectV1Request; //

const { status, data } = await apiInstance.signatureEditObjectV1(
    pkiSignatureID,
    signatureEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **signatureEditObjectV1Request** | **SignatureEditObjectV1Request**|  | |
| **pkiSignatureID** | [**number**] | The unique ID of the Signature | defaults to undefined|


### Return type

**SignatureEditObjectV1Response**

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

# **signatureGetObjectV2**
> SignatureGetObjectV2Response signatureGetObjectV2()



### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let pkiSignatureID: number; //The unique ID of the Signature (default to undefined)

const { status, data } = await apiInstance.signatureGetObjectV2(
    pkiSignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSignatureID** | [**number**] | The unique ID of the Signature | defaults to undefined|


### Return type

**SignatureGetObjectV2Response**

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

# **signatureGetObjectV3**
> SignatureGetObjectV3Response signatureGetObjectV3()



### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let pkiSignatureID: number; //The unique ID of the Signature (default to undefined)

const { status, data } = await apiInstance.signatureGetObjectV3(
    pkiSignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSignatureID** | [**number**] | The unique ID of the Signature | defaults to undefined|


### Return type

**SignatureGetObjectV3Response**

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

# **signatureGetSVGInitialsV1**
> signatureGetSVGInitialsV1()



### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let pkiSignatureID: number; //The unique ID of the Signature (default to undefined)

const { status, data } = await apiInstance.signatureGetSVGInitialsV1(
    pkiSignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSignatureID** | [**number**] | The unique ID of the Signature | defaults to undefined|


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

# **signatureGetSVGSignatureV1**
> signatureGetSVGSignatureV1()



### Example

```typescript
import {
    ObjectSignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSignatureApi(configuration);

let pkiSignatureID: number; //The unique ID of the Signature (default to undefined)

const { status, data } = await apiInstance.signatureGetSVGSignatureV1(
    pkiSignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiSignatureID** | [**number**] | The unique ID of the Signature | defaults to undefined|


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

