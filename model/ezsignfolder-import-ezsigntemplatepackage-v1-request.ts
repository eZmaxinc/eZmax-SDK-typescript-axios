/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


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
    'fkiEzsigntemplatepackageID': number;
    /**
     * The maximum date and time at which the Ezsigndocument can be signed.
     * @type {string}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1Request
     */
    'dtEzsigndocumentDuedate': string;
    /**
     * 
     * @type {Array<CustomImportEzsigntemplatepackageRelationRequest>}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1Request
     */
    'a_objImportEzsigntemplatepackageRelation': Array<CustomImportEzsigntemplatepackageRelationRequest>;
}

