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
import { EzsignbulksendCreateObjectV1ResponseMPayload } from './ezsignbulksend-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignbulksendCreateObjectV1ResponseAllOf
 */
export interface EzsignbulksendCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendCreateObjectV1ResponseMPayload}
     * @memberof EzsignbulksendCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsignbulksendCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendCreateObjectV1ResponseAllOf
 */
export class DataObjectEzsignbulksendCreateObjectV1ResponseAllOf {
   mPayload:EzsignbulksendCreateObjectV1ResponseMPayload = new DataObjectEzsignbulksendCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignbulksendCreateObjectV1ResponseAllOf
 */
export class ValidationObjectEzsignbulksendCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignbulksendCreateObjectV1ResponseMPayload()
} 


