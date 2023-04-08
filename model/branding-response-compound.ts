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


// May contain unused imports in some cases
// @ts-ignore
import { BrandingResponse } from './branding-response';
// May contain unused imports in some cases
// @ts-ignore
import { BrandingResponseCompoundAllOf } from './branding-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogo } from './field-ebranding-logo';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBrandingDescription } from './multilingual-branding-description';

/**
 * @type BrandingResponseCompound
 * A Branding Object
 * @export
 */
export type BrandingResponseCompound = BrandingResponse & BrandingResponseCompoundAllOf;



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualBrandingDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualBrandingDescription } from './'

/**
 * @export 
 * A BrandingResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingResponseCompound
 */
export class DataObjectBrandingResponseCompound {
   pkiBrandingID:number = 0
   objBrandingDescription:MultilingualBrandingDescription = new DataObjectMultilingualBrandingDescription()
   sBrandingDescriptionX:string = ''
   eBrandingLogo:FieldEBrandingLogo = 'Default'
   iBrandingColortext:number = 0
   iBrandingColortextlinkbox:number = 0
   iBrandingColortextbutton:number = 0
   iBrandingColorbackground:number = 0
   iBrandingColorbackgroundbutton:number = 0
   iBrandingColorbackgroundsmallbox:number = 0
   bBrandingIsactive:boolean = false
   sBrandingLogourl?:string = undefined
}

/**
 * @export 
 * A BrandingResponseCompound Validation Object
 * @class ValidationObjectBrandingResponseCompound
 */
export class ValidationObjectBrandingResponseCompound {
   pkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objBrandingDescription = new ValidationObjectMultilingualBrandingDescription()
   sBrandingDescriptionX = {
      type: 'string',
      required: true
   }
   eBrandingLogo = {
      type: 'enum',
      allowableValues: ['Default','JPEG','PNG'],
      required: true
   }
   iBrandingColortext = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColortextlinkbox = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColortextbutton = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColorbackground = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColorbackgroundbutton = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColorbackgroundsmallbox = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   bBrandingIsactive = {
      type: 'boolean',
      required: true
   }
   sBrandingLogourl = {
      type: 'string',
      required: false
   }
} 


