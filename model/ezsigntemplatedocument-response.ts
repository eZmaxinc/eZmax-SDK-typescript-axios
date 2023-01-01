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



import { DefaultObject } from '../base'

/**
 * A Ezsigntemplatedocument Object
 * @export
 * @interface EzsigntemplatedocumentResponse
 */
export interface EzsigntemplatedocumentResponse {
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    'pkiEzsigntemplatedocumentID': number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    'fkiEzsigntemplateID': number;
    /**
     * The name of the Ezsigntemplatedocument.
     * @type {string}
     * @memberof EzsigntemplatedocumentResponse
     */
    'sEzsigntemplatedocumentName': string;
    /**
     * The number of pages in the Ezsigntemplatedocument.
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    'iEzsigntemplatedocumentPagetotal': number;
    /**
     * The number of total signatures in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplatedocumentResponse
     */
    'iEzsigntemplatedocumentSignaturetotal': number;
}
/**
 * A EzsigntemplatedocumentResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentResponse
 */
export class DefaultObjectEzsigntemplatedocumentResponse extends DefaultObject {
   pkiEzsigntemplatedocumentID:number = 0
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatedocumentName:string = ''
   iEzsigntemplatedocumentPagetotal:number = 0
   iEzsigntemplatedocumentSignaturetotal:number = 0
}


