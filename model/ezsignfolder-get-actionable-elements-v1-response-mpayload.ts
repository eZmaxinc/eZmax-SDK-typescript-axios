/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsignformfieldgroupResponseCompound } from './ezsignformfieldgroup-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

/**
 * Payload for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getActionableElements
 * @export
 * @interface EzsignfolderGetActionableElementsV1ResponseMPayload
 */
export interface EzsignfolderGetActionableElementsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsignsignatureResponseCompound>}
     * @memberof EzsignfolderGetActionableElementsV1ResponseMPayload
     */
    /*'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;*/
    'a_objEzsignsignature': Array<EzsignsignatureResponseCompound>;
    /**
     * 
     * @type {Array<EzsignformfieldgroupResponseCompound>}
     * @memberof EzsignfolderGetActionableElementsV1ResponseMPayload
     */
    /*'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupResponseCompound>;*/
    'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderGetActionableElementsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetActionableElementsV1ResponseMPayload
 */
export class DataObjectEzsignfolderGetActionableElementsV1ResponseMPayload {
   a_objEzsignsignature:Array<EzsignsignatureResponseCompound> = []
   a_objEzsignformfieldgroup:Array<EzsignformfieldgroupResponseCompound> = []
}

/**
 * @export 
 * A EzsignfolderGetActionableElementsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderGetActionableElementsV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderGetActionableElementsV1ResponseMPayload {
   a_objEzsignsignature = {
      type: 'array',
      required: true
   }
   a_objEzsignformfieldgroup = {
      type: 'array',
      required: true
   }
} 


