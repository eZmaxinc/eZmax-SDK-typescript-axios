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
import { EzsigndocumentResponseCompound } from './ezsigndocument-response-compound';

/**
 * Payload for GET /1/object/ezsignfolder/{pkiEzsignfolder}/getEzsigndocuments
 * @export
 * @interface EzsignfolderGetEzsigndocumentsV1ResponseMPayload
 */
export interface EzsignfolderGetEzsigndocumentsV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigndocumentResponseCompound>}
     * @memberof EzsignfolderGetEzsigndocumentsV1ResponseMPayload
     */
    /*'a_objEzsigndocument': Array<EzsigndocumentResponseCompound>;*/
    'a_objEzsigndocument': Array<EzsigndocumentResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderGetEzsigndocumentsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload
 */
export class DataObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload {
   a_objEzsigndocument:Array<EzsigndocumentResponseCompound> = []
}

/**
 * @export 
 * A EzsignfolderGetEzsigndocumentsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload {
   a_objEzsigndocument = {
      type: 'array',
      required: true
   }
} 


