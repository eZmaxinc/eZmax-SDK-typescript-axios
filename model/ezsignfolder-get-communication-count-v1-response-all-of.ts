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
import { EzsignfolderGetCommunicationCountV1ResponseMPayload } from './ezsignfolder-get-communication-count-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderGetCommunicationCountV1ResponseAllOf
 */
export interface EzsignfolderGetCommunicationCountV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetCommunicationCountV1ResponseMPayload}
     * @memberof EzsignfolderGetCommunicationCountV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetCommunicationCountV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetCommunicationCountV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetCommunicationCountV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetCommunicationCountV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationCountV1ResponseAllOf
 */
export class DataObjectEzsignfolderGetCommunicationCountV1ResponseAllOf {
   mPayload:EzsignfolderGetCommunicationCountV1ResponseMPayload = new DataObjectEzsignfolderGetCommunicationCountV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetCommunicationCountV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationCountV1ResponseAllOf
 */
export class ValidationObjectEzsignfolderGetCommunicationCountV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderGetCommunicationCountV1ResponseMPayload()
} 


