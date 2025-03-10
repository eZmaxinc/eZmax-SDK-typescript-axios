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
import type { EzsigndocumentResponseCompound } from './ezsigndocument-response-compound';

/**
 * Payload for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage
 * @export
 * @interface EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
 */
export interface EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload {
    /**
     * 
     * @type {Array<EzsigndocumentResponseCompound>}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
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
 * A EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
 */
export class DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload {
   a_objEzsigndocument:Array<EzsigndocumentResponseCompound> = []
}

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload {
   a_objEzsigndocument = {
      type: 'array',
      required: true
   }
} 


