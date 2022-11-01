/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentResponseCompound } from './ezsigndocument-response-compound';

import { DefaultObject } from '../base'

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
    'a_objEzsigndocument': Array<EzsigndocumentResponseCompound>;
}
/**
 * A EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload
 */
export class DefaultObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload extends DefaultObject {
   a_objEzsigndocument:Array<EzsigndocumentResponseCompound> = []
}


