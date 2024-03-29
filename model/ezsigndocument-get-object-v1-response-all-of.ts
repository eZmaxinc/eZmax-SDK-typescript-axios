/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetObjectV1ResponseMPayload } from './ezsigndocument-get-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigndocumentGetObjectV1ResponseAllOf
 */
export interface EzsigndocumentGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentGetObjectV1ResponseMPayload}
     * @memberof EzsigndocumentGetObjectV1ResponseAllOf
     */
    'mPayload': EzsigndocumentGetObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetObjectV1ResponseAllOf
 */
export class DataObjectEzsigndocumentGetObjectV1ResponseAllOf {
   mPayload:EzsigndocumentGetObjectV1ResponseMPayload = new DataObjectEzsigndocumentGetObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigndocumentGetObjectV1ResponseAllOf
 */
export class ValidationObjectEzsigndocumentGetObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigndocumentGetObjectV1ResponseMPayload()
} 


