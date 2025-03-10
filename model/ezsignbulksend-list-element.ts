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



/**
 * An Ezsignbulksend List Element
 * @export
 * @interface EzsignbulksendListElement
 */
export interface EzsignbulksendListElement {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'pkiEzsignbulksendID': number;*/
    'pkiEzsignbulksendID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'fkiEzsignfoldertypeID': number;*/
    'fkiEzsignfoldertypeID': number;
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendListElement
     */
    /*'sEzsignbulksendDescription': string;*/
    'sEzsignbulksendDescription': string;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsignbulksendListElement
     */
    /*'sEzsignfoldertypeNameX': string;*/
    'sEzsignfoldertypeNameX': string;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendListElement
     */
    /*'bEzsignbulksendNeedvalidation': boolean;*/
    'bEzsignbulksendNeedvalidation': boolean;
    /**
     * The total number of Ezsignbulksendtransmissions in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'iEzsignbulksendtransmission': number;*/
    'iEzsignbulksendtransmission': number;
    /**
     * The total number of Ezsignfolders in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'iEzsignfolder': number;*/
    'iEzsignfolder': number;
    /**
     * The total number of Ezsigndocuments in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'iEzsigndocument': number;*/
    'iEzsigndocument': number;
    /**
     * The total number of Ezsignsignature in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'iEzsignsignature': number;*/
    'iEzsignsignature': number;
    /**
     * The total number of already signed Ezsignsignature blocks in the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendListElement
     */
    /*'iEzsignsignatureSigned': number;*/
    'iEzsignsignatureSigned': number;
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendListElement
     */
    /*'bEzsignbulksendIsactive': boolean;*/
    'bEzsignbulksendIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendListElement
 */
export class DataObjectEzsignbulksendListElement {
   pkiEzsignbulksendID:number = 0
   fkiEzsignfoldertypeID:number = 0
   sEzsignbulksendDescription:string = ''
   sEzsignfoldertypeNameX:string = ''
   bEzsignbulksendNeedvalidation:boolean = false
   iEzsignbulksendtransmission:number = 0
   iEzsignfolder:number = 0
   iEzsigndocument:number = 0
   iEzsignsignature:number = 0
   iEzsignsignatureSigned:number = 0
   bEzsignbulksendIsactive:boolean = false
}

/**
 * @export 
 * A EzsignbulksendListElement Validation Object
 * @class ValidationObjectEzsignbulksendListElement
 */
export class ValidationObjectEzsignbulksendListElement {
   pkiEzsignbulksendID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   sEzsignbulksendDescription = {
      type: 'string',
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   bEzsignbulksendNeedvalidation = {
      type: 'boolean',
      required: true
   }
   iEzsignbulksendtransmission = {
      type: 'integer',
      required: true
   }
   iEzsignfolder = {
      type: 'integer',
      required: true
   }
   iEzsigndocument = {
      type: 'integer',
      required: true
   }
   iEzsignsignature = {
      type: 'integer',
      required: true
   }
   iEzsignsignatureSigned = {
      type: 'integer',
      required: true
   }
   bEzsignbulksendIsactive = {
      type: 'boolean',
      required: true
   }
} 


