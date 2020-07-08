(function(){
	var tools = {
		// Remove the whitespace from the beginning and end of a string
		trim : function ( v )
			{
				return ( typeof v == 'string'  ) ? v.replace( /^\s+/, '' ).replace( /\s+$/, '' ) : v;
			},
	
		// Check if the value is defined and is not empty
		isEmpty: function ( v )
			{
				return ( typeof v == 'undefined' || /^\d*$/.test( v ) );
			},
		
		// Visits the Ad's URL
		visitUrl:	function( settings )
			{
				if( !this.isEmpty( settings[ 'adUrl' ] ) )
				{
					window.open( settings[ 'adUrl' ], settings[ 'target' ] );
				}
			}
	};
	
	var defaultSettings = { // Default settings
			alignTo		: 'tl',
			mirror 		: true,
			colorStart	: '#DADADA',
			colorIn		: '#DADADA',
			thumbPath 	: '',
			imgPath 	: '',
			audioPath	: '',
			adUrl 		: '',
			openIn		: -1,
			closeIn		: -1,
			target		: '_blank'
		};
	
	// Main function
	window[ 'printCornerAd' ] = function ( settings )
	{
		//*** PRIVATE FUNCTIONS ***
			
		// Images click
		function imgClick()
		{
			tools.visitUrl( settings );
		};
		
		// Leaf click
		function leafClickedActions()
		{
			if( typeof expanded == 'undefined' || expanded == false )
			{
				expandLeaf();
			}
			else
			{
				shrinkLeaf();
			}                  
		};

		//Expand 
		function expandLeaf()
		{
			expanded = true;

			//Make container grow big enough
			cornerContainer.css({'width':500,'height':500});
			
			//Show big image
			backgroundFillBig.show();

			//Show big image and animate it bigger so it doesn't show through
			backgroundFillBig.show().stop().animate( 
				{ path: pathBig }, 
				500, 
				'linear', 
				function()
				{
					// The closeIn is defined and the corner ad is expnaded
					if( settings[ 'closeIn' ] > 0 )
					{
						setTimeout( 
							function(){
								settings[ 'closeIn' ] = -1;
								if( expanded )
								{
									shrinkLeaf();
								}
							},
							settings[ 'closeIn' ]*1000
						)
					}
				} 
			);

			//Make leaf and shadow bigger
			setMirror( settings[ 'imgPath' ] );	
			pageLeaf.stop().animate( { path: pathLeafBig, transform:(isLeft)? 'T0,0' : 'T100,0' }, 500, 'linear' );
			pageLeafMirror.stop().animate( { path: pathLeafBig, transform:(isLeft)? 'T0,0' : 'T100,0' }, 500, 'linear' );
			pageLeafShadow.stop().animate( { path: pathLeafBig, transform: ( isLeft ) ? 'T-4,6' : 'T104,6' }, 500, 'linear' );
			
			//Hide small image
			backgroundFillSmall.hide();            
		};

		//Shrink it back
		function shrinkLeaf()
		{
			setTimeout(
				function()
				{
					expanded = false;
					
					//Shrink peel and shadow			
					pageLeaf.stop().animate( { path: pathLeaf, transform: (isLeft) ? 'T0,0':'T400,0' }, 400, 'linear' );
					pageLeafMirror.stop().animate( { path: pathLeaf, transform: (isLeft) ? 'T0,0':'T400,0' }, 400, 'linear' );
					pageLeafShadow.stop().animate( { transform: ( isLeft ) ? 'T-4,4' : 'T404,4', path: pathLeaf}, 400, 'linear' );

					//Hide big image and make it small again ready for animation
					backgroundFillBig.stop().animate( { path: pathSmall}, 400, 'linear',function(){
						//Show small advert again
						backgroundFillSmall.show();	
						
						//Fade big out
						backgroundFillBig.hide();
						
						setMirror( settings[ 'thumbPath' ] );
						
						//Make container shrink back
						cornerContainer.css( { 'width' : '100px', 'height' : '100px' } );
						
						// Swing leaf
						swingLeaf();
					});	        
				},
				500
			);	
		};
		
		// Swing the leaf
		var swingTo = 0;
		function swingLeaf()
		{
			swingTo = ( swingTo + 1 ) % 2;
			pageLeaf.stop().animate( { path: ( swingTo ) ? pathLeafSwung : pathLeaf }, 1500, 'linear', function(){ swingLeaf();} ); 
			pageLeafMirror.stop().animate( { path: ( swingTo ) ? pathLeafSwung : pathLeaf }, 1500, 'linear' ); 
			pageLeafShadow.stop().animate( { path: ( swingTo ) ? pathLeafSwung : pathLeaf }, 1500, 'linear' ); 
		};
			
		// Assign image as mirror
		function setMirror( url )
		{
			if( settings[ 'mirror' ] )
			{
				function flipImage( e, width )
				{
					if( typeof width == 'undefined' )
					{
						setTimeout(
							function()
							{
								flipImage( e, e.attr( 'width' ) );
							},
							20
						);
						return;
					}
					else
					{
						e[ 0 ].setAttribute( 'transform', 'scale(-1,1) translate('+( -1 * width )+',0)' );
					}
				};

				pageLeaf.attr( 'fill', 'url("'+url+'")' );
				var patternSelector = $( pageLeaf.node )
										.attr( 'fill' )
										.replace( 'url(#', '' )
										.replace( ')', '' ),
					img 	= $( '#'+patternSelector+' image' ),
					width 	= img.attr( 'width' );

				if( typeof width == 'undefined' )
				{
					flipImage( img );
				}
				else
				{
					flipImage( img, width );
				}
			}
		};
		// Main Code	
		var $ = jQuery,
			isLeft = true,
			cornerContainer;
		
		// Extending settings
		settings = $.extend( {}, defaultSettings, settings );
		
		// Remove the extra white-spaces form settings
		for( var i in settings )
		{
			settings[ i ] = tools.trim( settings[ i ] );
		}
		
		// Open the Corner Ad at left or right
		if( settings[ 'alignTo' ] == 'tr' )
		{
			isLeft = false;
		}
		
		// Correct target attribute
		if( settings[ 'target' ] == '_blank' )
		{
			settings[ 'target' ] = 'cornerAdLink';
		}
		
		// Create the audio player
		if( !tools.isEmpty( settings[ 'audioPath' ] ) )
		{
			
			$( 'body' ).append( $('<div style="display:none;width:1px;heigth:1px;"><audio src="'+settings[ 'audioPath' ]+'" autoplay loop preload="auto"/></div>') );
		}
		
		// Create the corner ad
		if( !tools.isEmpty( settings[ 'imgPath' ] ) )
		{
			// Initialize thumbnail path
			if( tools.isEmpty( settings[ 'thumbPath' ] ) ) settings[ 'thumbPath' ] = settings[ 'imgPath' ];
			
			// DIV tag to insert the cornerAd
			cornerContainer = $( '#cornerContainer' );
			if( cornerContainer.length == 0 ){ 
				cornerContainer = $( '<div id="cornerContainer"></div>' );
				$( 'body' ).append( cornerContainer );
			}
			cornerContainer
				.attr( 'style',  'position:absolute;width:100px;height:100px;top:0;z-index:999999;overflow:hidden;'+( ( isLeft) ? 'left' : 'right' )+':0;' )
				.html( '<div style="position:absolute;'+( ( isLeft ) ? 'left' : 'right' )+':0;"></div>' );
			
			// Create the SVG paper where generate the corner ad
			var paper = new Raphael( cornerContainer.find('div')[ 0 ], 500, 500 );
			
			// Paths definitions
			var pathSmall 	  = ( isLeft ) ? 'M 0,0 H 100 L 0,100 Z' : 'M 400,0 L 500,100 L 500,0 Z',
				pathBig   	  = ( isLeft ) ? 'M 0,0 H 400 L 0,400 Z' : 'M 100,0 L 500,400 L 500,0 Z',
				pathLeaf  	  = ( isLeft ) ? 'M 100,0 Q 75,25 75,75 Q 25,75 0,100 Z' : 'M 0,0 Q 25,25 25,75 Q 75,75 100,100 Z',
				pathLeafBig   = ( isLeft ) ? 'M 400,0 Q 300,150 300,300 Q 150,300 0,400 Z' : 'M 0,0 Q 100,100 100,300 Q 300,300 400,400 Z',
				pathLeafSwung = ( isLeft ) ? 'M 100,0 Q 75,25 75,90 Q 25,75 0,100 Z' : 'M 0,0 Q 25,25 25,90 Q 75,75 100,100 Z';
				
			// Paths
			var backgroundFillSmall = paper.path( pathSmall ),	
				backgroundFillBig 	= paper.path( pathBig ),
				pageLeafShadow 		= paper.path( pathLeaf ),
				pageLeaf 			= paper.path( pathLeaf ),
				pageLeafMirror 		= paper.path( pathLeaf );
				
			
			// Path attributes
			var	bgFillSmallAttrs = { fill: "url('" + settings[ 'thumbPath' ] + "')", 'stroke-width':0 },
				bgFillBigAttrs = { fill: "url('" + settings[ 'imgPath' ] + "')", 'stroke-width':0,'id':'BigAdvert' },
				gradient = ( isLeft ) ? '315-' + settings[ 'colorStart' ] + '-' + settings[ 'colorIn' ] : '225-' + settings[ 'colorStart' ] + '-' + settings[ 'colorIn' ],
				leafAttrs = { 
					'id': 'cornerLeaf',
					'gradient': gradient,
					'stroke-width' : 0, 
					'opacity': 1
				},
				leafMirrorAttrs = { 
					'gradient': gradient,
					'stroke-width' : 0, 
					'opacity': 0.3 
				},
				leafShadowAttrs = { fill: settings[ 'colorStart' ], 'opacity': 0.6, 'stroke-width':0 };

			// Load Images 
			backgroundFillSmall.attr( bgFillSmallAttrs );
			backgroundFillBig.attr( bgFillBigAttrs );
			
			//Make cursor as pointer on hover
			backgroundFillSmall.node.setAttribute( 'style', 'cursor:pointer' );
			backgroundFillBig.node.setAttribute( 'style', 'cursor:pointer' );
			pageLeafMirror.node.setAttribute( 'style', 'cursor:pointer' );

			// Reduce and hide the big image
			backgroundFillBig.animate( { path: pathSmall }, 1, 'linear' );
			backgroundFillBig.hide();
			
			//Configure leaf shadow
			pageLeafShadow.attr( leafShadowAttrs );
			pageLeafShadow.transform( ( isLeft ) ? 'T-4,4' : 'T404,4');
			
		
			//Configure leaf
			pageLeaf.attr( leafAttrs );
			setMirror( settings[ 'thumbPath' ] );
			pageLeaf.transform( ( isLeft ) ? 'T0,0': 'T400,0');
			// and mirror
			pageLeafMirror.attr( leafMirrorAttrs );
			pageLeafMirror.transform( ( isLeft ) ? 'T0,0': 'T400,0');

			//Initial little shimmy to make people look
			swingLeaf();
			
			//*** EVENTS ***
			//Leaf expand on hover and click
			pageLeafMirror.click(
				function()
				{
					leafClickedActions();
				}
			);
			
			$( pageLeafMirror.node ).mouseenter( 
				function()
				{
					leafClickedActions();
				}
			);
			// Shrink leaf if mouse leave
			$(backgroundFillBig.node).mouseleave(
				function()
				{
					shrinkLeaf();
				}
			);
			
			//Advert click
			backgroundFillSmall.click(
				function()
				{
					imgClick();
				}
			);
			
			backgroundFillBig.click( 
				function()
				{
					imgClick();
				}
			);

			// Check the dynamic open close leaf
			if( settings[ 'openIn' ] > 0 )
			{
				setTimeout( 
					function()
					{ 
						settings[ 'openIn' ] = -1;
						if( typeof expanded == 'undefined' || expanded == false )
						{
							expandLeaf();
						}	
					},  
					settings[ 'openIn' ]*1000 
				);
			}
		}
	};
})();