/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Ezsignbulksenddocumentmapping Object
 * @export
 * @interface EzsignbulksenddocumentmappingRequest
 */
export interface EzsignbulksenddocumentmappingRequest {
    /**
     * The unique ID of the Ezsignbulksenddocumentmapping.
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingRequest
     */
    'pkiEzsignbulksenddocumentmappingID'?: number;
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingRequest
     */
    'fkiEzsignbulksendID': number;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingRequest
     */
    'fkiEzsigntemplatepackageID'?: number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsignbulksenddocumentmappingRequest
     */
    'fkiEzsigntemplateID'?: number;
}
/**
 * A EzsignbulksenddocumentmappingRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksenddocumentmappingRequest
 */
export class DefaultObjectEzsignbulksenddocumentmappingRequest extends DefaultObject {
   pkiEzsignbulksenddocumentmappingID?:number = undefined
   fkiEzsignbulksendID:number = 0
   fkiEzsigntemplatepackageID?:number = undefined
   fkiEzsigntemplateID?:number = undefined
}


