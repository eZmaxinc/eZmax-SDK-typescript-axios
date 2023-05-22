/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetListV1ResponseMPayload } from './ezsignfolder-get-list-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderGetListV1ResponseAllOf
 */
export interface EzsignfolderGetListV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetListV1ResponseMPayload}
     * @memberof EzsignfolderGetListV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetListV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetListV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetListV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetListV1ResponseAllOf
 */
export class DataObjectEzsignfolderGetListV1ResponseAllOf {
   mPayload:EzsignfolderGetListV1ResponseMPayload = new DataObjectEzsignfolderGetListV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetListV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderGetListV1ResponseAllOf
 */
export class ValidationObjectEzsignfolderGetListV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderGetListV1ResponseMPayload()
} 


