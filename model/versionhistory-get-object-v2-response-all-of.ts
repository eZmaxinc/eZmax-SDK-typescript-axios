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
import { VersionhistoryGetObjectV2ResponseMPayload } from './versionhistory-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface VersionhistoryGetObjectV2ResponseAllOf
 */
export interface VersionhistoryGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {VersionhistoryGetObjectV2ResponseMPayload}
     * @memberof VersionhistoryGetObjectV2ResponseAllOf
     */
    'mPayload': VersionhistoryGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectVersionhistoryGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectVersionhistoryGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A VersionhistoryGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectVersionhistoryGetObjectV2ResponseAllOf
 */
export class DataObjectVersionhistoryGetObjectV2ResponseAllOf {
   mPayload:VersionhistoryGetObjectV2ResponseMPayload = new DataObjectVersionhistoryGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A VersionhistoryGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectVersionhistoryGetObjectV2ResponseAllOf
 */
export class ValidationObjectVersionhistoryGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectVersionhistoryGetObjectV2ResponseMPayload()
} 


