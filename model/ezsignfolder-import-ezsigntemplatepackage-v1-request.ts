/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomImportEzsigntemplatepackageRelationRequest } from './custom-import-ezsigntemplatepackage-relation-request';

/**
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/importEzsigntemplatepackage
 * @export
 * @interface EzsignfolderImportEzsigntemplatepackageV1Request
 */
export interface EzsignfolderImportEzsigntemplatepackageV1Request {
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1Request
     */
    /*'fkiEzsigntemplatepackageID': number;*/
    'fkiEzsigntemplatepackageID': number;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1Request
     */
    /*'dtEzsigndocumentDuedate': string;*/
    'dtEzsigndocumentDuedate': string;
    /**
     * 
     * @type {Array<CustomImportEzsigntemplatepackageRelationRequest>}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1Request
     */
    /*'a_objImportEzsigntemplatepackageRelation': Array<CustomImportEzsigntemplatepackageRelationRequest>;*/
    'a_objImportEzsigntemplatepackageRelation': Array<CustomImportEzsigntemplatepackageRelationRequest>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsigntemplatepackageV1Request
 */
export class DataObjectEzsignfolderImportEzsigntemplatepackageV1Request {
   fkiEzsigntemplatepackageID:number = 0
   dtEzsigndocumentDuedate:string = ''
   a_objImportEzsigntemplatepackageRelation:Array<CustomImportEzsigntemplatepackageRelationRequest> = []
}

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1Request Validation Object
 * @class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1Request
 */
export class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1Request {
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dtEzsigndocumentDuedate = {
      type: 'string',
      required: true
   }
   a_objImportEzsigntemplatepackageRelation = {
      type: 'array',
      required: true
   }
} 


