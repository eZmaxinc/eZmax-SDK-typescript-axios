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
import { EzsignfolderGetObjectV1ResponseMPayload } from './ezsignfolder-get-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderGetObjectV1ResponseAllOf
 */
export interface EzsignfolderGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetObjectV1ResponseMPayload}
     * @memberof EzsignfolderGetObjectV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetObjectV1ResponseAllOf
 */
export class DataObjectEzsignfolderGetObjectV1ResponseAllOf {
   mPayload:EzsignfolderGetObjectV1ResponseMPayload = new DataObjectEzsignfolderGetObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderGetObjectV1ResponseAllOf
 */
export class ValidationObjectEzsignfolderGetObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderGetObjectV1ResponseMPayload()
} 


