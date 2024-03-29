/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingRequest } from './branding-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogo } from './field-ebranding-logo';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBrandingDescription } from './multilingual-branding-description';

/**
 * @type BrandingRequestCompound
 * A Branding Object and children
 * @export
 */
export type BrandingRequestCompound = BrandingRequest;



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
 * A BrandingRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingRequestCompound
 */
export class DataObjectBrandingRequestCompound {
    pkiBrandingID?:number = undefined
    objBrandingDescription:MultilingualBrandingDescription = new DataObjectMultilingualBrandingDescription()
    eBrandingLogo:FieldEBrandingLogo = 'Default'
    sBrandingBase64?:string = undefined
    iBrandingColortext:number = 0
    iBrandingColortextlinkbox:number = 0
    iBrandingColortextbutton:number = 0
    iBrandingColorbackground:number = 0
    iBrandingColorbackgroundbutton:number = 0
    iBrandingColorbackgroundsmallbox:number = 0
    sBrandingName?:string = undefined
    sEmailAddress?:string = undefined
    bBrandingIsactive:boolean = false
}

/**
 * @export 
 * A BrandingRequestCompound Validation Object
 * @class ValidationObjectBrandingRequestCompound
 */
export class ValidationObjectBrandingRequestCompound {
   pkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objBrandingDescription = new ValidationObjectMultilingualBrandingDescription()
   eBrandingLogo = {
      type: 'enum',
      allowableValues: ['Default','JPEG','PNG'],
      required: true
   }
   sBrandingBase64 = {
      type: 'string',
      required: false
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
   sBrandingName = {
      type: 'string',
      pattern: '/^.{0,55}$/',
      required: false
   }
   sEmailAddress = {
      type: 'string',
      required: false
   }
   bBrandingIsactive = {
      type: 'boolean',
      required: true
   }
} 


