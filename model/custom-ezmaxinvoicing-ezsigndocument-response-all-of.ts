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



import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CustomEzmaxinvoicingEzsigndocumentResponseAllOf
 */
export interface CustomEzmaxinvoicingEzsigndocumentResponseAllOf {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponseAllOf
     */
    'fkiEzsignfolderID': number;
    /**
     * 
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponseAllOf
     */
    'sName': string;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponseAllOf
     */
    'sEzsignfolderDescription': string;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponseAllOf
     */
    'sEzsigndocumentName': string;
    /**
     * 
     * @type {boolean}
     * @memberof CustomEzmaxinvoicingEzsigndocumentResponseAllOf
     */
    'bEzsignfolderAllowed': boolean;
}
/**
 * A CustomEzmaxinvoicingEzsigndocumentResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomEzmaxinvoicingEzsigndocumentResponseAllOf
 */
export class DefaultObjectCustomEzmaxinvoicingEzsigndocumentResponseAllOf extends DefaultObject {
   fkiEzsignfolderID:number = 0
   sName:string = ''
   sEzsignfolderDescription:string = ''
   sEzsigndocumentName:string = ''
   bEzsignfolderAllowed:boolean = false
}


