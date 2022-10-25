/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Ezsigntemplate List Element
 * @export
 * @interface EzsigntemplateListElement
 */
export interface EzsigntemplateListElement {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    'pkiEzsigntemplateID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateListElement
     */
    'sEzsigntemplateDescription': string;
    /**
     * The number of pages in the Ezsigntemplatedocument.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    'iEzsigntemplatedocumentPagetotal'?: number;
    /**
     * The number of total signatures in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    'iEzsigntemplateSignaturetotal'?: number;
    /**
     * The number of total form fields in the Ezsigntemplate.
     * @type {number}
     * @memberof EzsigntemplateListElement
     */
    'iEzsigntemplateFormfieldtotal'?: number;
    /**
     * Indicate the Ezsigntemplate is incomplete and cannot be used
     * @type {boolean}
     * @memberof EzsigntemplateListElement
     */
    'bEzsigntemplateIncomplete': boolean;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateListElement
     */
    'sEzsignfoldertypeNameX': string;
}
/**
 * A EzsigntemplateListElement Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateListElement
 */
export class DefaultObjectEzsigntemplateListElement extends DefaultObject {
   pkiEzsigntemplateID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsigntemplateDescription:string = ''
   iEzsigntemplatedocumentPagetotal?:number = undefined
   iEzsigntemplateSignaturetotal?:number = undefined
   iEzsigntemplateFormfieldtotal?:number = undefined
   bEzsigntemplateIncomplete:boolean = false
   sEzsignfoldertypeNameX:string = ''
}


