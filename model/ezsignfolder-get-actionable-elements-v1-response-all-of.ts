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
import { EzsignfolderGetActionableElementsV1ResponseMPayload } from './ezsignfolder-get-actionable-elements-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderGetActionableElementsV1ResponseAllOf
 */
export interface EzsignfolderGetActionableElementsV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetActionableElementsV1ResponseMPayload}
     * @memberof EzsignfolderGetActionableElementsV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetActionableElementsV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetActionableElementsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetActionableElementsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetActionableElementsV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetActionableElementsV1ResponseAllOf
 */
export class DataObjectEzsignfolderGetActionableElementsV1ResponseAllOf {
   mPayload:EzsignfolderGetActionableElementsV1ResponseMPayload = new DataObjectEzsignfolderGetActionableElementsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetActionableElementsV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderGetActionableElementsV1ResponseAllOf
 */
export class ValidationObjectEzsignfolderGetActionableElementsV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderGetActionableElementsV1ResponseMPayload()
} 


