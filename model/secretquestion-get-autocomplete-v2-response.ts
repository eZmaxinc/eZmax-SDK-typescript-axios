/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { SecretquestionGetAutocompleteV2ResponseMPayload } from './secretquestion-get-autocomplete-v2-response-mpayload';

/**
 * @type SecretquestionGetAutocompleteV2Response
 * Response for GET /2/object/secretquestion/getAutocomplete
 * @export
 */
/** export type SecretquestionGetAutocompleteV2Response = CommonResponse; */
export interface SecretquestionGetAutocompleteV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof SecretquestionGetAutocompleteV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof SecretquestionGetAutocompleteV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {SecretquestionGetAutocompleteV2ResponseMPayload}
     * @memberof SecretquestionGetAutocompleteV2Response
     */
    mPayload:SecretquestionGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectSecretquestionGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectSecretquestionGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A SecretquestionGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSecretquestionGetAutocompleteV2Response
 */
export class DataObjectSecretquestionGetAutocompleteV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:SecretquestionGetAutocompleteV2ResponseMPayload = new DataObjectSecretquestionGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A SecretquestionGetAutocompleteV2Response Validation Object
 * @class ValidationObjectSecretquestionGetAutocompleteV2Response
 */
export class ValidationObjectSecretquestionGetAutocompleteV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectSecretquestionGetAutocompleteV2ResponseMPayload()
} 


