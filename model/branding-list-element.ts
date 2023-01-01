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
 * A Branding List Element
 * @export
 * @interface BrandingListElement
 */
export interface BrandingListElement {
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof BrandingListElement
     */
    'pkiBrandingID': number;
    /**
     * The Description of the Branding in the language of the requester
     * @type {string}
     * @memberof BrandingListElement
     */
    'sBrandingDescriptionX': string;
    /**
     * The color of the text. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingListElement
     */
    'iBrandingColortext': number;
    /**
     * The color of the text in the link box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingListElement
     */
    'iBrandingColortextlinkbox': number;
    /**
     * The color of the text in the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingListElement
     */
    'iBrandingColortextbutton': number;
    /**
     * The color of the background. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingListElement
     */
    'iBrandingColorbackground': number;
    /**
     * The color of the background of the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingListElement
     */
    'iBrandingColorbackgroundbutton': number;
    /**
     * The color of the background of the small box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingListElement
     */
    'iBrandingColorbackgroundsmallbox': number;
    /**
     * Whether the Branding is active or not
     * @type {boolean}
     * @memberof BrandingListElement
     */
    'bBrandingIsactive': boolean;
}
/**
 * A BrandingListElement Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingListElement
 */
export class DefaultObjectBrandingListElement extends DefaultObject {
   pkiBrandingID:number = 0
   sBrandingDescriptionX:string = ''
   iBrandingColortext:number = 0
   iBrandingColortextlinkbox:number = 0
   iBrandingColortextbutton:number = 0
   iBrandingColorbackground:number = 0
   iBrandingColorbackgroundbutton:number = 0
   iBrandingColorbackgroundsmallbox:number = 0
   bBrandingIsactive:boolean = false
}


